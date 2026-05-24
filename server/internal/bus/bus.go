// Package bus is the durable event transport between the ingest tier and the processing
// tier. The interface lets ingest stay decoupled from workers; backpressure and replay
// come from NATS JetStream in production, while an in-process memory bus powers the
// all-in-one binary with no external dependency.
package bus

import (
	"errors"
	"sync"
	"sync/atomic"
)

// SubjectEvents is the subject raw events are published to.
const SubjectEvents = "events.raw"

// errBusClosed is returned by Publish after the bus has been closed.
var errBusClosed = errors.New("bus: closed")

// Handler processes one message body. Returning an error means the message should be retried
// by durable buses that support explicit acknowledgement.
type Handler func(data []byte) error

// Bus is a minimal publish/consume abstraction.
//
// Subscribe registers a durable consumer identified by `consumer`. Replicas that share a
// consumer name load-balance messages (queue semantics); distinct consumer names each
// receive every message (fan-out). This is what lets stateless processors scale via a
// queue group while the stateful correlator runs as its own consumer.
type Bus interface {
	Publish(subject string, data []byte) error
	Subscribe(subject, consumer string, h Handler) error
	Close() error
}

// Open returns a NATS-backed bus when url is set, else an in-process memory bus.
func Open(url string) (Bus, error) {
	if url == "" {
		return newMemoryBus(), nil
	}
	return newNatsBus(url)
}

// ---------- in-process memory bus ----------

type memoryBus struct {
	mu        sync.RWMutex
	consumers map[string]*consumerGroup // key: subject|consumer
	closed    bool
}

type consumerGroup struct {
	handlers []Handler
	rr       atomic.Uint64 // round-robin cursor for queue semantics
}

func newMemoryBus() *memoryBus {
	return &memoryBus{consumers: map[string]*consumerGroup{}}
}

func (m *memoryBus) Publish(subject string, data []byte) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return errBusClosed
	}
	var groups []*consumerGroup
	for key, g := range m.consumers {
		if hasPrefix(key, subject+"|") {
			groups = append(groups, g)
		}
	}
	m.mu.RUnlock()
	for _, g := range groups {
		if len(g.handlers) == 0 {
			continue
		}
		idx := int(g.rr.Add(1)-1) % len(g.handlers) // load-balance within the group
		// copy so concurrent consumers can't race on the same backing array
		buf := make([]byte, len(data))
		copy(buf, data)
		go func(h Handler, body []byte) { _ = h(body) }(g.handlers[idx], buf)
	}
	return nil
}

func (m *memoryBus) Subscribe(subject, consumer string, h Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := subject + "|" + consumer
	g := m.consumers[key]
	if g == nil {
		g = &consumerGroup{}
		m.consumers[key] = g
	}
	g.handlers = append(g.handlers, h)
	return nil
}

func (m *memoryBus) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
