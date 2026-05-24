package bus

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryBusDeliversToConsumer(t *testing.T) {
	m := newMemoryBus()
	var got int32
	var wg sync.WaitGroup
	wg.Add(1)
	_ = m.Subscribe(SubjectEvents, "g1", func(b []byte) error {
		atomic.AddInt32(&got, 1)
		wg.Done()
		return nil
	})
	if err := m.Publish(SubjectEvents, []byte("e")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not invoked")
	}
	if atomic.LoadInt32(&got) != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
}

func TestMemoryBusPublishAfterCloseFails(t *testing.T) {
	m := newMemoryBus()
	_ = m.Close()
	if err := m.Publish(SubjectEvents, []byte("e")); err == nil {
		t.Fatal("Publish after Close must return an error (no handlers fired post-shutdown)")
	}
}

// Queue semantics: two handlers in one consumer group share the load (not both invoked per msg).
func TestMemoryBusQueueGroupLoadBalances(t *testing.T) {
	m := newMemoryBus()
	var a, b int32
	_ = m.Subscribe(SubjectEvents, "grp", func([]byte) error { atomic.AddInt32(&a, 1); return nil })
	_ = m.Subscribe(SubjectEvents, "grp", func([]byte) error { atomic.AddInt32(&b, 1); return nil })
	for i := 0; i < 10; i++ {
		_ = m.Publish(SubjectEvents, []byte("x"))
	}
	time.Sleep(200 * time.Millisecond)
	total := atomic.LoadInt32(&a) + atomic.LoadInt32(&b)
	if total != 10 {
		t.Fatalf("group should receive each message once: total=%d", total)
	}
}
