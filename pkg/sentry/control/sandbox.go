// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Sandbox includes task-related functions.
type Sandbox struct {
	Kernel             *kernel.Kernel
	Ch                 chan struct{}
	MountNamespace     *fs.MountNamespace
	MountNamespaceVFS2 *vfs.MountNamespace
	NumContainers      int32
	containersStarted  int32
}

// ContainerArgs is the set of arguments to start a container.
type ContainerArgs struct {
	// Filename is the filename to load.
	//
	// If this is provided as "", then the file will be guessed via Argv[0].
	Filename string `json:"filename"`

	// Argv is a list of arguments.
	Argv []string `json:"argv"`

	// Envv is a list of environment variables.
	Envv []string `json:"envv"`

	// WorkingDirectory defines the working directory for the new process.
	WorkingDirectory string `json:"wd"`

	// KUID is the UID to run with in the root user namespace. Defaults to
	// root if not set explicitly.
	KUID auth.KUID

	// KGID is the GID to run with in the root user namespace. Defaults to
	// the root group if not set explicitly.
	KGID auth.KGID

	// ExtraKGIDs is the list of additional groups to which the user belongs.
	ExtraKGIDs []auth.KGID

	// Capabilities is the list of capabilities to give to the process.
	Capabilities *auth.TaskCapabilities

	// StdioIsPty indicates that FDs 0, 1, and 2 are connected to a host pty FD.
	StdioIsPty bool

	// FilePayload determines the files to give to the new process.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string

	// Limits is the limit set for the process being executed.
	Limits *limits.LimitSet

	// MountRootConf is the root mount.
	MountRootConf SentryMount

	// SubMountConf contains the submounts.
	SubMountConf []SentryMount

	// MountFd is the fd which should be used to mount.
	MountFd int
}

// SentryMount contains the mount config for the container.
type SentryMount struct {
	Target string
	FsType string
}

// String prints the arguments as a string.
func (args ContainerArgs) String() string {
	if len(args.Argv) == 0 {
		return args.Filename
	}
	a := make([]string, len(args.Argv))
	copy(a, args.Argv)
	if args.Filename != "" {
		a[0] = args.Filename
	}
	return strings.Join(a, " ")
}

func (s *Sandbox) createNewMountNamespace(ctx context.Context, creds *auth.Credentials, fsType string, fd int) (*vfs.MountNamespace, error) {
	data := []string{
		"trans=fd",
		"rfdno=" + strconv.Itoa(fd),
		"wfdno=" + strconv.Itoa(fd),
	}

	opts := &vfs.MountOptions{
		ReadOnly: true,
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: strings.Join(data, ","),
			InternalData: gofer.InternalFilesystemOptions{
				UniqueID: "/",
			},
		},
		InternalMount: true,
	}
	rootCreds := auth.NewRootCredentials(creds.UserNamespace)
	mns, err := s.Kernel.VFS().NewMountNamespace(ctx, rootCreds, "", fsType, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to construct MountNamespace: %v", err)
	}

	// TODO: Mount submounts.
	return mns, nil
}

// StartContainer will start a new container in the sandbox.
func (s *Sandbox) StartContainer(args *ContainerArgs, _ *uint32) error {
	// Import file descriptors.
	fdTable := s.Kernel.NewFDTable()

	creds := auth.NewUserCredentials(
		args.KUID,
		args.KGID,
		args.ExtraKGIDs,
		args.Capabilities,
		s.Kernel.RootUserNamespace())

	limitSet := args.Limits
	if limitSet == nil {
		limitSet = limits.NewLimitSet()
	}
	initArgs := kernel.CreateProcessArgs{
		Filename:                args.Filename,
		Argv:                    args.Argv,
		Envv:                    args.Envv,
		WorkingDirectory:        args.WorkingDirectory,
		Credentials:             creds,
		FDTable:                 fdTable,
		Umask:                   0022,
		Limits:                  limitSet,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            s.Kernel.RootUTSNamespace(),
		IPCNamespace:            s.Kernel.RootIPCNamespace(),
		AbstractSocketNamespace: s.Kernel.RootAbstractSocketNamespace(),
		ContainerID:             args.ContainerID,
		PIDNamespace:            s.Kernel.RootPIDNamespace().NewChild(s.Kernel.RootUserNamespace()),
		MountNamespace:          s.MountNamespace,
		MountNamespaceVFS2:      s.MountNamespaceVFS2,
	}

	ctx := initArgs.NewContext(s.Kernel)
	defer fdTable.DecRef(ctx)

	if kernel.VFS2Enabled && s.containersStarted >= 1 {
		// Create new mount namespace from second container. For the
		// first container, the mount namespace will be passed as an
		// argument during container start.
		mntns, err := s.createNewMountNamespace(ctx, creds, "9p", args.MountFd)
		if err != nil {
			return err
		}
		initArgs.MountNamespaceVFS2 = mntns
		initArgs.MountNamespaceVFS2.IncRef()
	}

	resolved, err := user.ResolveExecutablePath(ctx, &initArgs)
	if err != nil {
		return err
	}
	initArgs.Filename = resolved

	fds, err := fd.NewFromFiles(args.Files)
	if err != nil {
		return fmt.Errorf("duplicating payload files: %w", err)
	}
	defer func() {
		for _, fd := range fds {
			_ = fd.Close()
		}
	}()

	tg, _, err := s.Kernel.CreateProcess(initArgs)
	if err != nil {
		return err
	}

	// Start the newly created process.
	s.Kernel.StartProcess(tg)
	log.Infof("Started the new container %v %v", s.containersStarted, s.NumContainers)

	s.containersStarted++
	if s.NumContainers == s.containersStarted {
		s.Ch <- struct{}{}
	}
	return nil
}
