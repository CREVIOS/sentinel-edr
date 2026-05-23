// Package transport defines the control-plane interfaces that decouple producers
// (pipeline, response orchestrator) from how messages reach consoles and agents.
// Two implementations satisfy them: the in-process hub (all-in-one) and a NATS mesh
// (horizontally scaled deployments).
package transport

import (
	"time"

	"github.com/sentinel/server/internal/model"
)

// Broadcaster fans a UI update out to every connected console.
type Broadcaster interface {
	Broadcast(typ string, data any)
}

// Commander delivers a containment command to a specific agent and awaits its result.
type Commander interface {
	SendCommand(agentID string, cmd model.Command, timeout time.Duration) (model.CommandResult, bool)
	AgentOnline(agentID string) bool
}
