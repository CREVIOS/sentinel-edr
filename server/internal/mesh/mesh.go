// Package mesh implements the control plane over NATS core for horizontally scaled
// deployments: console broadcasts fan out to every gateway, and containment commands are
// routed to whichever gateway currently holds the target agent's WebSocket. In all-in-one
// mode the in-process hub satisfies the same transport interfaces and mesh is not used.
package mesh

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sentinel/server/internal/hub"
	"github.com/sentinel/server/internal/model"
)

const (
	subjConsole   = "console"
	subjCmdPrefix = "cmd."
	subjPresence  = "presence."
)

type consoleMsg struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// Mesh is the NATS-backed Broadcaster + Commander.
type Mesh struct {
	nc *nats.Conn
}

// New connects to NATS for control-plane messaging.
func New(url string) (*Mesh, error) {
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.Name("sentinel-mesh"),
	)
	if err != nil {
		return nil, err
	}
	return &Mesh{nc: nc}, nil
}

// Broadcast publishes a console update to all gateways.
func (m *Mesh) Broadcast(typ string, data any) {
	b, err := json.Marshal(consoleMsg{Type: typ, Data: data})
	if err != nil {
		return
	}
	_ = m.nc.Publish(subjConsole, b)
}

// SendCommand routes a command to the gateway holding the agent and waits for its result.
func (m *Mesh) SendCommand(agentID string, cmd model.Command, timeout time.Duration) (model.CommandResult, bool) {
	b, _ := json.Marshal(cmd)
	msg, err := m.nc.Request(subjCmdPrefix+agentID, b, timeout)
	if err != nil {
		return model.CommandResult{ID: cmd.ID, OK: false, Message: "no gateway holds agent: " + err.Error()}, false
	}
	var res model.CommandResult
	if json.Unmarshal(msg.Data, &res) != nil {
		return model.CommandResult{ID: cmd.ID, OK: false, Message: "bad gateway reply"}, false
	}
	return res, true
}

// AgentOnline asks the mesh whether any gateway holds the agent.
func (m *Mesh) AgentOnline(agentID string) bool {
	msg, err := m.nc.Request(subjPresence+agentID, nil, time.Second)
	return err == nil && msg != nil && string(msg.Data) == "1"
}

// Close tears down the NATS connection.
func (m *Mesh) Close() { m.nc.Close() }

// BridgeGateway wires a gateway's local hub to the mesh:
//   - console broadcasts from the cluster are written to this gateway's console clients
//   - command/presence requests for locally-held agents are answered from this gateway
func BridgeGateway(url string, h *hub.Hub) (*nats.Conn, error) {
	nc, err := nats.Connect(url, nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second), nats.Name("sentinel-gateway"))
	if err != nil {
		return nil, err
	}
	// Fan cluster-wide console updates into this gateway's local WebSocket clients.
	_, err = nc.Subscribe(subjConsole, func(msg *nats.Msg) {
		var cm consoleMsg
		if json.Unmarshal(msg.Data, &cm) == nil {
			h.Broadcast(cm.Type, cm.Data)
		}
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	// Answer command requests only for agents whose WebSocket lives on this gateway.
	_, err = nc.Subscribe(subjCmdPrefix+"*", func(msg *nats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, subjCmdPrefix)
		if !h.AgentOnline(agentID) {
			return // another gateway owns this agent
		}
		var cmd model.Command
		if json.Unmarshal(msg.Data, &cmd) != nil {
			return
		}
		res, _ := h.SendCommand(agentID, cmd, 8*time.Second)
		b, _ := json.Marshal(res)
		_ = msg.Respond(b)
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	// Presence answers for locally-held agents.
	_, err = nc.Subscribe(subjPresence+"*", func(msg *nats.Msg) {
		agentID := strings.TrimPrefix(msg.Subject, subjPresence)
		if h.AgentOnline(agentID) {
			_ = msg.Respond([]byte("1"))
		}
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return nc, nil
}
