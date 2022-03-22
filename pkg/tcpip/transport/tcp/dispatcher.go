// Copyright 2018 The gVisor Authors.
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

package tcp

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// epQueue is a queue of endpoints.
type epQueue struct {
	mu   sync.Mutex
	list endpointList
}

// enqueue adds e to the queue if the endpoint is not already on the queue.
func (q *epQueue) enqueue(e *endpoint) {
	q.mu.Lock()
	e.pendingProcessingMu.Lock()
	if e.pendingProcessing {
		e.pendingProcessingMu.Unlock()
		q.mu.Unlock()
		return
	}
	q.list.PushBack(e)
	e.pendingProcessing = true
	e.pendingProcessingMu.Unlock()
	q.mu.Unlock()
}

// dequeue removes and returns the first element from the queue if available,
// returns nil otherwise.
func (q *epQueue) dequeue() *endpoint {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		q.list.Remove(e)
		e.pendingProcessingMu.Lock()
		e.pendingProcessing = false
		e.pendingProcessingMu.Unlock()
		q.mu.Unlock()
		return e
	}
	q.mu.Unlock()
	return nil
}

// empty returns true if the queue is empty, false otherwise.
func (q *epQueue) empty() bool {
	q.mu.Lock()
	v := q.list.Empty()
	q.mu.Unlock()
	return v
}

// processor is responsible for processing packets queued to a tcp endpoint.
type processor struct {
	epQ              epQueue
	sleeper          sleep.Sleeper
	newEndpointWaker sleep.Waker
	closeWaker       sleep.Waker
}

func (p *processor) close() {
	p.closeWaker.Assert()
}

func (p *processor) queueEndpoint(ep *endpoint) {
	// Queue an endpoint for processing by the processor goroutine.
	p.epQ.enqueue(ep)
	p.newEndpointWaker.Assert()
}

const (
	newEndpointWaker = 1
	closeWaker       = 2
)

// +checklocks:ep.mu
func deliverAccepted(ep *endpoint) bool {
	lEP := ep.h.listenEP
	lEP.acceptMu.Lock()

	// Remove endpoint from list of pendingEndpoints as the handshake
	// is now complete.
	delete(lEP.acceptQueue.pendingEndpoints, ep)
	// Deliver this endpoint to the listening socket's accept queue.
	if lEP.acceptQueue.capacity == 0 {
		lEP.acceptMu.Unlock()
		return false
	}
	lEP.acceptQueue.endpoints.PushBack(ep)
	lEP.acceptMu.Unlock()
	ep.h.listenEP.waiterQueue.Notify(waiter.ReadableEvents)

	return true
}

// handleConnecting is responsible for TCP processing for an endpoint
// in one of the connecting states.
func (p *processor) handleConnecting(ep *endpoint) {
	if !ep.TryLock() {
		return
	}
	cleanup := func() {
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
	if !ep.EndpointState().connecting() {
		// If the endpoint has already transitioned out of a connecting
		// stage then just return (only possible if it was closed or
		// timed out by the time we got around to processing the
		// wakeup.
		ep.mu.Unlock()
		return
	}
	if err := ep.h.processSegments(); err != nil { // +checklocksforce:ep.h.ep.mu
		// handshake failed. clean up the tcp endpoint and handshake
		// state.
		ep.handshakeFailed(err)
		cleanup()
		return
	}

	if ep.EndpointState() == StateEstablished && ep.h.listenEP != nil {
		ep.isConnectNotified = true
		ep.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
		if !deliverAccepted(ep) {
			ep.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			cleanup()
			return
		}
	}
	ep.mu.Unlock()
}

// handleConnected is responsible for TCP processing for an endpoint in
// one of the connected states(StateEstablished, StateFinWait1 etc.)
func (p *processor) handleConnected(ep *endpoint) {
	if !ep.TryLock() {
		return
	}

	// NOTE: We read this outside of e.mu lock which means that by the time
	// we get to handleSegments the endpoint may not be in ESTABLISHED. But
	// this should be fine as all normal shutdown states are handled by
	// handleSegments and if the endpoint moves to a CLOSED/ERROR state
	// then handleSegments is a noop.
	// If the endpoint is in a connected state then we do direct delivery
	// to ensure low latency and avoid scheduler interactions.
	switch err := ep.handleSegmentsLocked(true /* fastPath */); { // +checklocksforce:
	case err != nil:
		// Send any active resets if required.
		ep.resetConnectionLocked(err)
		fallthrough
	case ep.EndpointState() == StateClose:
		ep.mu.Unlock()
		ep.stack.Stats().TCP.CurrentConnected.Decrement()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	case ep.EndpointState() == StateTimeWait:
		p.startTimeWait(ep) // +checklocksforce:ep.mu
	}
	ep.mu.Unlock() // +checklocksforce
}

// startTimeWait starts a new goroutine to handle TIME-WAIT.
// +checklocks:ep.mu
func (p *processor) startTimeWait(ep *endpoint) {
	// Disable close timer as we are now entering real TIME_WAIT.
	if ep.finWait2Timer != nil {
		ep.finWait2Timer.Stop()
	}
	// Wake up any waiters before we start TIME-WAIT.
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	timeWaitDuration := ep.getTimeWaitDuration()
	ep.timeWaitTimer = ep.stack.Clock().AfterFunc(timeWaitDuration, ep.timeWaitTimerExpired)
}

func (p *processor) handleTimeWait(ep *endpoint) {
	if !ep.TryLock() {
		return
	}

	extendTimeWait, reuseTW := ep.handleTimeWaitSegments()
	if reuseTW != nil {
		ep.transitionToStateCloseLocked()
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		reuseTW()
		return
	}
	if extendTimeWait {
		ep.timeWaitTimer.Reset(ep.getTimeWaitDuration())
	}
	ep.mu.Unlock()
}

func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.sleeper.Done()

	for {
		if w := p.sleeper.Fetch(true); w == &p.closeWaker {
			break
		}
		// If not the closeWaker, it must be &p.newEndpointWaker.
		for {
			ep := p.epQ.dequeue()
			if ep == nil {
				break
			}
			if ep.segmentQueue.empty() {
				continue
			}
			switch state := ep.EndpointState(); {
			case state.connecting():
				p.handleConnecting(ep)
			case state.connected() && state != StateTimeWait:
				p.handleConnected(ep)
			case state == StateTimeWait:
				p.handleTimeWait(ep)
			case state == StateListen:
				// TODO(bhaskerh): get rid of listen loop.
				ep.newSegmentWaker.Assert()
				continue
			case state == StateError || state == StateClose:
				// Try to redeliver any still queued packets to another endpoint
				// or send a RST if it can't be delivered.
				ep.mu.Lock()
				if st := ep.EndpointState(); st == StateError || st == StateClose {
					ep.drainClosingSegmentQueue()
				}
				ep.mu.Unlock()
			default:
				panic(fmt.Sprintf("unexpected tcp state in processor: %v", state))
			}
			// If there are more segments to process then requeue
			// this endpoint for processing.
			if !ep.segmentQueue.empty() {
				p.epQ.enqueue(ep)
			}
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. The processor is selected based on the
// hash of the endpoint id to ensure that delivery for the same endpoint happens
// in-order.
type dispatcher struct {
	processors []processor
	wg         sync.WaitGroup
	hasher     jenkinsHasher
	mu         sync.Mutex
	closed     bool
}

func (d *dispatcher) init(rng *rand.Rand, nProcessors int) {
	d.close()
	d.wait()
	d.closed = false
	d.processors = make([]processor, nProcessors)
	d.hasher = jenkinsHasher{seed: rng.Uint32()}
	for i := range d.processors {
		p := &d.processors[i]
		p.sleeper.AddWaker(&p.newEndpointWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		d.wg.Add(1)
		// NB: sleeper-waker registration must happen synchronously to avoid races
		// with `close`.  It's possible to pull all this logic into `start`, but
		// that results in a heap-allocated function literal.
		go p.start(&d.wg)
	}
}

func (d *dispatcher) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for i := range d.processors {
		d.processors[i].close()
	}
}

func (d *dispatcher) wait() {
	d.wg.Wait()
}

func (d *dispatcher) queuePacket(stackEP stack.TransportEndpoint, id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return
	}

	ep := stackEP.(*endpoint)

	s := newIncomingSegment(id, clock, pkt)
	defer s.DecRef()
	if !s.parse(pkt.RXTransportChecksumValidated) {
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}

	if !s.csumValid {
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		return
	}

	d.selectProcessor(id).queueEndpoint(ep)
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {

	return &d.processors[d.hasher.hash(id)%uint32(len(d.processors))]
}

type jenkinsHasher struct {
	seed uint32
}

func (j jenkinsHasher) hash(id stack.TransportEndpointID) uint32 {
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], id.LocalPort)
	binary.LittleEndian.PutUint16(payload[2:], id.RemotePort)

	h := jenkins.Sum32(j.seed)
	h.Write(payload[:])
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))
	return h.Sum32()
}
