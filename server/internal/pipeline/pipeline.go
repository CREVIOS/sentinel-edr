// Package pipeline is the processing tier. It consumes events from the bus and runs them
// through the Sigma detection engine, the DLP engine and (optionally) the behavioral
// correlator, persisting results, streaming them to consoles, and triggering automated
// responses. Stateless processors scale horizontally via a shared bus consumer group; the
// stateful correlator runs as its own consumer so it observes the full event stream.
package pipeline

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/behavior"
	"github.com/sentinel/server/internal/bus"
	"github.com/sentinel/server/internal/detect"
	"github.com/sentinel/server/internal/dlp"
	"github.com/sentinel/server/internal/intel"
	"github.com/sentinel/server/internal/model"
	"github.com/sentinel/server/internal/respond"
	"github.com/sentinel/server/internal/store"
	"github.com/sentinel/server/internal/transport"
)

// Processor wires the detection/DLP/behavior engines to the store and transport.
type Processor struct {
	store    store.Store
	detect   *detect.Engine
	dlp      *dlp.Engine
	behavior *behavior.Engine
	respond  *respond.Orchestrator
	bcast    transport.Broadcaster
	intel    *intel.Engine
	log      *slog.Logger
}

// New creates a Processor.
func New(s store.Store, d *detect.Engine, dl *dlp.Engine, b *behavior.Engine, r *respond.Orchestrator, bc transport.Broadcaster, log *slog.Logger) *Processor {
	return &Processor{store: s, detect: d, dlp: dl, behavior: b, respond: r, bcast: bc, log: log}
}

// WithIntel attaches a threat-intel (IOC) engine. Optional; nil → no IOC matching.
func (p *Processor) WithIntel(e *intel.Engine) *Processor { p.intel = e; return p }

// StartProcessors subscribes the stateless detection/DLP consumer (queue group).
func (p *Processor) StartProcessors(b bus.Bus) error {
	return b.Subscribe(bus.SubjectEvents, "processors", func(data []byte) error {
		var ev model.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			// Poison message: ACK (return nil) so it doesn't block the consumer forever,
			// but make it visible — never silently drop telemetry without a trace.
			p.log.Error("drop undecodable event", "err", err, "bytes", len(data))
			return nil
		}
		return p.processStateless(ev)
	})
}

// StartCorrelator subscribes the stateful behavioral consumer (sees every event).
func (p *Processor) StartCorrelator(b bus.Bus) error {
	if p.behavior == nil {
		return nil
	}
	return b.Subscribe(bus.SubjectEvents, "correlator", func(data []byte) error {
		var ev model.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			p.log.Error("correlator drop undecodable event", "err", err, "bytes", len(data))
			return nil
		}
		var errs []error
		for _, d := range p.behavior.Observe(&ev) {
			if err := p.emit(d, &ev, behaviorAction(d.RuleID)); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

func (p *Processor) processStateless(ev model.Event) error {
	if err := p.store.InsertEvents([]model.Event{ev}); err != nil {
		p.log.Error("persist event", "err", err)
		return err
	}
	p.bcast.Broadcast("event", ev)

	var errs []error
	for _, d := range p.detect.Eval(&ev) {
		if err := p.emit(d, &ev, p.detect.AutoRespondFor(d.RuleID)); err != nil {
			errs = append(errs, err)
		}
	}
	// Threat-intel IOC matching (hash/ip/domain) — emits its own detections.
	if p.intel != nil {
		for _, d := range p.intel.Match(&ev) {
			if err := p.emit(d, &ev, ""); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := p.runDLP(&ev); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// runDLP turns DLP findings into detections and (for block verdicts) responses.
func (p *Processor) runDLP(ev *model.Event) error {
	// Agent already classified this transfer.
	if ev.Category == model.CatDLP && ev.DLP != nil {
		d := dlpDetection(ev, ev.DLP)
		return p.emit(d, ev, dlpAction(ev.DLP))
	}
	// Defense in depth: re-inspect any content the agent attached.
	content, _ := ev.Extra["content"].(string)
	if content == "" {
		return nil
	}
	var errs []error
	channel := dlpChannel(ev)
	for _, f := range p.dlp.Scan(content) {
		verdict := p.dlp.Verdict(f.Classifier, channel)
		if verdict == "audit" {
			continue
		}
		info := &model.DLPInfo{Classifier: f.Classifier, Channel: channel, Matches: f.Matches, Sample: f.Sample, Verdict: verdict}
		// synthesize a DLP event so it shows in the DLP view
		de := *ev
		de.ID = uuid.NewString()
		de.Category = model.CatDLP
		de.Action = "content_match"
		de.Severity = f.Severity
		de.DLP = info
		de.Message = f.Label + " detected on " + channel
		if err := p.store.InsertEvents([]model.Event{de}); err != nil {
			p.log.Error("persist dlp event", "err", err)
			errs = append(errs, err)
			continue
		}
		p.bcast.Broadcast("event", de)
		d := dlpDetection(&de, info)
		if err := p.emit(d, &de, dlpAction(info)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Processor) emit(d *model.Detection, ev *model.Event, action string) error {
	if err := p.store.InsertDetection(d); err != nil {
		p.log.Error("persist detection", "err", err)
		return err
	}
	p.bcast.Broadcast("detection", d)
	if p.respond != nil && action != "" {
		if r := p.respond.AutoFromDetection(d, ev, action); r != nil {
			p.log.Info("auto-response", "type", r.Type, "agent", r.AgentID, "status", r.Status)
		}
	}
	return nil
}

func dlpDetection(ev *model.Event, info *model.DLPInfo) *model.Detection {
	sev := ev.Severity
	if sev == "" {
		sev = model.SevHigh
	}
	mitre := []string{"T1052"} // exfil over physical medium
	tactic := "Exfiltration"
	switch info.Channel {
	case "scp", "rsync", "ftp", "http_upload", "cloud":
		mitre = []string{"T1567"} // exfil over web service
	}
	return &model.Detection{
		ID:       uuid.NewString(),
		TS:       time.Now().UTC(),
		RuleID:   "dlp-" + info.Classifier,
		RuleName: "DLP: " + info.Classifier + " via " + info.Channel,
		Severity: sev,
		Category: model.CatDLP,
		AgentID:  ev.AgentID,
		Hostname: ev.Hostname,
		User:     ev.User,
		Summary:  ev.Message,
		MITRE:    mitre,
		Tactic:   tactic,
		Status:   model.DetOpen,
		EventIDs: []string{ev.ID},
		Engine:   "dlp",
	}
}

// dlpAction maps a blocking DLP verdict to a containment action.
func dlpAction(info *model.DLPInfo) string {
	if info.Verdict != "block" {
		return ""
	}
	if info.Channel == "usb" {
		return string(model.RespBlockUSB)
	}
	return string(model.RespBlockUpload)
}

func dlpChannel(ev *model.Event) string {
	if ev.USB != nil {
		return "usb"
	}
	if ev.Network != nil {
		switch ev.Network.Category {
		case "cloud_storage":
			return "cloud"
		case "webmail":
			return "email"
		}
		return "http_upload"
	}
	if ev.Process != nil {
		switch ev.Process.Name {
		case "scp":
			return "scp"
		case "rsync":
			return "rsync"
		case "ftp", "sftp":
			return "ftp"
		}
	}
	return "file"
}

func behaviorAction(ruleID string) string {
	switch ruleID {
	case "behavior-usb-mass-copy":
		return string(model.RespBlockUSB)
	case "behavior-data-exfil-volume":
		return string(model.RespBlockUpload)
	}
	return ""
}
