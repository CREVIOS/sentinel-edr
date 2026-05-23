// Package respond is the response orchestrator. It turns analyst- or rule-initiated
// actions into commands delivered to agents (via the transport: hub or NATS mesh),
// persists their lifecycle, and keeps agent state (e.g. isolated) consistent. Supported
// actions: kill process, isolate / un-isolate endpoint, disable account, block upload,
// block USB.
package respond

import (
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
	"github.com/sentinel/server/internal/store"
	"github.com/sentinel/server/internal/transport"
)

// Orchestrator coordinates response actions.
type Orchestrator struct {
	store store.Store
	cmd   transport.Commander
	bcast transport.Broadcaster
}

// New creates an orchestrator.
func New(s store.Store, cmd transport.Commander, bcast transport.Broadcaster) *Orchestrator {
	return &Orchestrator{store: s, cmd: cmd, bcast: bcast}
}

// Issue persists, dispatches and finalizes a response action, blocking briefly for the
// agent's acknowledgement.
func (o *Orchestrator) Issue(a *model.ResponseAction) (*model.ResponseAction, error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	a.Status = model.RespPending
	if ag, err := o.store.GetAgent(a.AgentID); err == nil {
		a.Hostname = ag.Hostname
	}
	if err := o.store.InsertResponse(a); err != nil {
		return nil, err
	}
	o.bcast.Broadcast("response", a)

	cmd := model.Command{ID: a.ID, Type: a.Type, Target: a.Target}
	res, delivered := o.cmd.SendCommand(a.AgentID, cmd, 8*time.Second)
	if !delivered {
		a.Status = model.RespFailed
		a.Result = res.Message
		_ = o.store.InsertResponse(a)
		o.bcast.Broadcast("response", a)
		return a, nil
	}

	if res.OK {
		a.Status = model.RespDone
	} else {
		a.Status = model.RespFailed
	}
	a.Result = res.Message

	switch a.Type {
	case model.RespIsolate:
		if res.OK {
			_ = o.store.SetAgentStatus(a.AgentID, model.StatusIsolated)
		}
	case model.RespUnisolate:
		if res.OK {
			_ = o.store.SetAgentStatus(a.AgentID, model.StatusOnline)
		}
	}

	_ = o.store.InsertResponse(a)
	o.bcast.Broadcast("response", a)
	if ag, err := o.store.GetAgent(a.AgentID); err == nil {
		o.bcast.Broadcast("agent", ag)
	}
	return a, nil
}

// AutoFromDetection builds and issues an automated response derived from a detection and
// the event that triggered it. Returns nil if no action is mapped.
func (o *Orchestrator) AutoFromDetection(d *model.Detection, ev *model.Event, action string) *model.ResponseAction {
	if action == "" {
		return nil
	}
	a := &model.ResponseAction{
		Type:        model.ResponseType(action),
		AgentID:     d.AgentID,
		Reason:      "Automated response: " + d.RuleName,
		IssuedBy:    "auto-response",
		DetectionID: d.ID,
		Automated:   true,
		Target:      map[string]any{},
	}
	switch model.ResponseType(action) {
	case model.RespKillProcess:
		if ev != nil && ev.Process != nil && ev.Process.PID > 0 {
			a.Target["pid"] = ev.Process.PID
			a.Target["name"] = ev.Process.Name
		} else {
			return nil
		}
	case model.RespDisableAccount:
		switch {
		case d.User != "":
			a.Target["user"] = d.User
		case ev != nil && ev.User != "":
			a.Target["user"] = ev.User
		default:
			return nil
		}
	case model.RespBlockUpload, model.RespIsolate, model.RespBlockUSB:
		// no extra target needed
	default:
		return nil
	}
	out, err := o.Issue(a)
	if err != nil {
		return nil
	}
	return out
}
