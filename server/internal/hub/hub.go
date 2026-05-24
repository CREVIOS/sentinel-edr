// Package hub manages WebSocket connections: a broadcast feed for console clients and a
// per-agent command channel used by the response orchestrator to push containment actions.
package hub

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sentinel/server/internal/model"
)

// Message is the envelope pushed to console clients.
type Message struct {
	Type string `json:"type"` // event|detection|response|agent|stats
	Data any    `json:"data"`
}

// Hub fans out messages to consoles and routes commands to agents.
type Hub struct {
	mu        sync.RWMutex
	consoles  map[*websocket.Conn]*sync.Mutex // value = per-conn write lock
	agents    map[string]*agentConn
	pending   map[string]chan model.CommandResult
	pendingMu sync.Mutex
}

type agentConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// New creates an empty hub.
func New() *Hub {
	return &Hub{
		consoles: map[*websocket.Conn]*sync.Mutex{},
		agents:   map[string]*agentConn{},
		pending:  map[string]chan model.CommandResult{},
	}
}

// AddConsole registers a console websocket.
func (h *Hub) AddConsole(c *websocket.Conn) {
	h.mu.Lock()
	h.consoles[c] = &sync.Mutex{}
	h.mu.Unlock()
}

// RemoveConsole unregisters a console websocket.
func (h *Hub) RemoveConsole(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.consoles, c)
	h.mu.Unlock()
	_ = c.Close()
}

// AddAgent registers an agent command channel.
func (h *Hub) AddAgent(id string, c *websocket.Conn) {
	h.mu.Lock()
	h.agents[id] = &agentConn{conn: c}
	h.mu.Unlock()
}

// RemoveAgent unregisters an agent command channel.
func (h *Hub) RemoveAgent(id string) {
	h.mu.Lock()
	if a, ok := h.agents[id]; ok {
		_ = a.conn.Close()
		delete(h.agents, id)
	}
	h.mu.Unlock()
}

// AgentOnline reports whether an agent has a live command channel.
func (h *Hub) AgentOnline(id string) bool {
	h.mu.RLock()
	_, ok := h.agents[id]
	h.mu.RUnlock()
	return ok
}

// Broadcast sends a message to every console client.
func (h *Hub) Broadcast(typ string, data any) {
	msg := Message{Type: typ, Data: data}
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	type target struct {
		c  *websocket.Conn
		wl *sync.Mutex
	}
	h.mu.RLock()
	conns := make([]target, 0, len(h.consoles))
	for c, wl := range h.consoles {
		conns = append(conns, target{c, wl})
	}
	h.mu.RUnlock()
	for _, t := range conns {
		// Serialize writes per console — concurrent Broadcast calls (pipeline + correlator +
		// API) would otherwise write the same socket simultaneously (gorilla panics on that).
		t.wl.Lock()
		_ = t.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := t.c.WriteMessage(websocket.TextMessage, b)
		t.wl.Unlock()
		if err != nil {
			h.RemoveConsole(t.c)
		}
	}
}

// SendCommand pushes a command to an agent and waits up to timeout for its result.
func (h *Hub) SendCommand(agentID string, cmd model.Command, timeout time.Duration) (model.CommandResult, bool) {
	h.mu.RLock()
	a, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return model.CommandResult{ID: cmd.ID, OK: false, Message: "agent offline"}, false
	}
	ch := make(chan model.CommandResult, 1)
	h.pendingMu.Lock()
	h.pending[cmd.ID] = ch
	h.pendingMu.Unlock()
	defer func() {
		h.pendingMu.Lock()
		delete(h.pending, cmd.ID)
		h.pendingMu.Unlock()
	}()

	b, _ := json.Marshal(cmd)
	a.mu.Lock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := a.conn.WriteMessage(websocket.TextMessage, b)
	a.mu.Unlock()
	if err != nil {
		return model.CommandResult{ID: cmd.ID, OK: false, Message: "send failed: " + err.Error()}, false
	}
	select {
	case res := <-ch:
		return res, true
	case <-time.After(timeout):
		return model.CommandResult{ID: cmd.ID, OK: false, Message: "agent timeout"}, false
	}
}

// PingAgent sends a WebSocket ping to an agent (serialized with command writes via the
// per-agent lock). Used to detect half-open connections so dead agent goroutines don't leak.
func (h *Hub) PingAgent(id string) bool {
	h.mu.RLock()
	a, ok := h.agents[id]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	a.mu.Lock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := a.conn.WriteMessage(websocket.PingMessage, nil)
	a.mu.Unlock()
	return err == nil
}

// DeliverResult routes an agent's command reply back to the waiting caller.
func (h *Hub) DeliverResult(res model.CommandResult) {
	h.pendingMu.Lock()
	ch, ok := h.pending[res.ID]
	h.pendingMu.Unlock()
	if ok {
		select {
		case ch <- res:
		default:
		}
	}
}
