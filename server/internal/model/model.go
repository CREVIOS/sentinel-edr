// Package model defines the shared wire + storage contract for the whole platform.
// The Rust agent serializes events to this exact JSON shape; the Go server stores and
// evaluates them; the React console renders them. Keep field names stable.
package model

import "time"

// Severity is an ordered threat level used by events, detections and alerts.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank returns a numeric ordering so severities can be compared/sorted.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Category groups events by the monitoring domain that produced them.
type Category string

const (
	CatAuth    Category = "auth"    // login/logout
	CatSSH     Category = "ssh"     // ssh + privileged access
	CatProcess Category = "process" // command execution / process activity
	CatFile    Category = "file"    // file access / modify / delete (FIM)
	CatPackage Category = "package" // package + system config changes
	CatUSB     Category = "usb"     // removable device usage
	CatNetwork Category = "network" // internet / browser / DNS / connections
	CatDLP     Category = "dlp"     // data-loss-prevention findings
	CatSystem  Category = "system"  // agent lifecycle / heartbeat
)

// Process describes the process associated with an event.
type Process struct {
	PID       int    `json:"pid,omitempty"`
	PPID      int    `json:"ppid,omitempty"`
	Name      string `json:"name,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	UID       int    `json:"uid,omitempty"`
	User      string `json:"user,omitempty"`
	Parent    string `json:"parent,omitempty"`    // immediate parent process name
	Lineage   string `json:"lineage,omitempty"`   // full ancestry chain (pid1→…→self)
	Container string `json:"container,omitempty"` // container id+runtime if running in one
}

// FileInfo describes a filesystem operation.
type FileInfo struct {
	Path  string `json:"path,omitempty"`
	Op    string `json:"op,omitempty"` // create|write|read|delete|rename|chmod
	Size  int64  `json:"size,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Hash  string `json:"hash,omitempty"` // sha256
	IsDir bool   `json:"is_dir,omitempty"`
}

// NetInfo describes a network/browser event.
type NetInfo struct {
	Direction string `json:"direction,omitempty"` // inbound|outbound
	Proto     string `json:"proto,omitempty"`     // tcp|udp|dns|http|https
	LocalAddr string `json:"local_addr,omitempty"`
	Remote    string `json:"remote,omitempty"`   // ip:port
	Domain    string `json:"domain,omitempty"`   // resolved/visited host
	URL       string `json:"url,omitempty"`      // full url if browser
	Category  string `json:"category,omitempty"` // webmail|cloud_storage|social|...
	BytesOut  int64  `json:"bytes_out,omitempty"`
	BytesIn   int64  `json:"bytes_in,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
}

// USBInfo describes a removable device event.
type USBInfo struct {
	Action  string `json:"action,omitempty"` // insert|remove|mount|write
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Serial  string `json:"serial,omitempty"`
	Mount   string `json:"mount,omitempty"`
	SizeGB  int    `json:"size_gb,omitempty"`
}

// AuthInfo describes a login / privileged-access event.
type AuthInfo struct {
	Method   string `json:"method,omitempty"` // password|pubkey|sudo|su
	SourceIP string `json:"source_ip,omitempty"`
	TTY      string `json:"tty,omitempty"`
	Result   string `json:"result,omitempty"` // success|failure
}

// DLPInfo describes a data-loss-prevention finding attached to an event.
type DLPInfo struct {
	Classifier string `json:"classifier,omitempty"` // pii_ssn|pci_card|secret_key|source_code
	Channel    string `json:"channel,omitempty"`    // usb|scp|rsync|http_upload|email|cloud
	Matches    int    `json:"matches,omitempty"`
	Sample     string `json:"sample,omitempty"` // redacted sample
	Policy     string `json:"policy,omitempty"`
	Verdict    string `json:"verdict,omitempty"` // audit|alert|block
}

// Event is the universal envelope every collector emits.
type Event struct {
	ID       string         `json:"id"`
	AgentID  string         `json:"agent_id"`
	Hostname string         `json:"hostname"`
	TS       time.Time      `json:"ts"`
	Category Category       `json:"category"`
	Action   string         `json:"action"`
	Severity Severity       `json:"severity"`
	User     string         `json:"user,omitempty"`
	Message  string         `json:"message,omitempty"`
	Process  *Process       `json:"process,omitempty"`
	File     *FileInfo      `json:"file,omitempty"`
	Network  *NetInfo       `json:"network,omitempty"`
	USB      *USBInfo       `json:"usb,omitempty"`
	Auth     *AuthInfo      `json:"auth,omitempty"`
	DLP      *DLPInfo       `json:"dlp,omitempty"`
	Labels   []string       `json:"labels,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// EventBatch is what the agent POSTs to /api/v1/events.
type EventBatch struct {
	AgentID string  `json:"agent_id"`
	Events  []Event `json:"events"`
}

// AgentStatus is the lifecycle state of an enrolled endpoint.
type AgentStatus string

const (
	StatusOnline   AgentStatus = "online"
	StatusOffline  AgentStatus = "offline"
	StatusIsolated AgentStatus = "isolated"
)

// Agent is an enrolled endpoint.
type Agent struct {
	ID         string      `json:"id"`
	Hostname   string      `json:"hostname"`
	OS         string      `json:"os"`
	Kernel     string      `json:"kernel"`
	Arch       string      `json:"arch"`
	IP         string      `json:"ip"`
	MAC        string      `json:"mac"`
	Version    string      `json:"version"`
	Status     AgentStatus `json:"status"`
	Labels     []string    `json:"labels,omitempty"`
	EnrolledAt time.Time   `json:"enrolled_at"`
	LastSeen   time.Time   `json:"last_seen"`
	EventCount int64       `json:"event_count"`
	// Key is the per-agent shared secret; never serialized to the console.
	Key string `json:"-"`
}

// Detection is a fired rule or behavioral finding.
type DetectionStatus string

const (
	DetOpen   DetectionStatus = "open"
	DetAck    DetectionStatus = "acknowledged"
	DetClosed DetectionStatus = "closed"
)

// Detection links one or more events to a rule and an ATT&CK technique.
type Detection struct {
	ID         string          `json:"id"`
	TS         time.Time       `json:"ts"`
	RuleID     string          `json:"rule_id"`
	RuleName   string          `json:"rule_name"`
	Severity   Severity        `json:"severity"`
	Category   Category        `json:"category"`
	AgentID    string          `json:"agent_id"`
	Hostname   string          `json:"hostname"`
	User       string          `json:"user,omitempty"`
	Summary    string          `json:"summary"`
	MITRE      []string        `json:"mitre,omitempty"` // technique ids e.g. T1059
	Tactic     string          `json:"tactic,omitempty"`
	Status     DetectionStatus `json:"status"`
	EventIDs   []string        `json:"event_ids,omitempty"`
	Engine     string          `json:"engine"` // sigma|behavior|dlp
	AssignedTo string          `json:"assigned_to,omitempty"`
}

// ResponseAction is an automated or analyst-issued containment action.
type ResponseType string

const (
	RespKillProcess    ResponseType = "kill_process"
	RespKillTree       ResponseType = "kill_tree"
	RespIsolate        ResponseType = "isolate"
	RespUnisolate      ResponseType = "unisolate"
	RespDisableAccount ResponseType = "disable_account"
	RespBlockUpload    ResponseType = "block_upload"
	RespBlockUSB       ResponseType = "block_usb"
	RespFreeze         ResponseType = "freeze"
	RespUnfreeze       ResponseType = "unfreeze"
	RespQuarantine     ResponseType = "quarantine_file"
	RespLiveTriage     ResponseType = "live_triage"
	// Fleet-management commands (not containment): hot-reload policy + verified self-update.
	RespUpdatePolicy ResponseType = "update_policy"
	RespSelfUpdate   ResponseType = "self_update"
)

type ResponseStatus string

const (
	RespPending ResponseStatus = "pending"
	RespSent    ResponseStatus = "sent"
	RespAcked   ResponseStatus = "acknowledged"
	RespDone    ResponseStatus = "completed"
	RespFailed  ResponseStatus = "failed"
)

// ResponseAction is dispatched to an agent over its command channel.
type ResponseAction struct {
	ID          string         `json:"id"`
	TS          time.Time      `json:"ts"`
	Type        ResponseType   `json:"type"`
	AgentID     string         `json:"agent_id"`
	Hostname    string         `json:"hostname"`
	Target      map[string]any `json:"target"` // {pid:..} {user:..} etc
	Reason      string         `json:"reason"`
	IssuedBy    string         `json:"issued_by"`
	DetectionID string         `json:"detection_id,omitempty"`
	Status      ResponseStatus `json:"status"`
	Result      string         `json:"result,omitempty"`
	Automated   bool           `json:"automated"`
}

// ---------- incident / case management ----------

// CaseStatus is the lifecycle of an investigation.
type CaseStatus string

const (
	CaseOpen          CaseStatus = "open"
	CaseInvestigating CaseStatus = "investigating"
	CaseContained     CaseStatus = "contained"
	CaseClosed        CaseStatus = "closed"
)

// CaseNote is a timestamped analyst note on a case.
type CaseNote struct {
	TS     time.Time `json:"ts"`
	Author string    `json:"author"`
	Body   string    `json:"body"`
}

// Case groups related detections into a single investigation. Detections are correlated
// into an open case per endpoint within a time window, or analysts create/curate cases.
type Case struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Severity     Severity   `json:"severity"`
	Status       CaseStatus `json:"status"`
	AssignedTo   string     `json:"assigned_to,omitempty"`
	AgentID      string     `json:"agent_id,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	DetectionIDs []string   `json:"detection_ids"`
	MITRE        []string   `json:"mitre,omitempty"`
	Notes        []CaseNote `json:"notes,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    string     `json:"created_by,omitempty"`
}

// ---------- detection tuning ----------

// Suppression silences detections that match a rule + field predicate, so known-benign
// activity stops generating noise without disabling the rule globally.
type Suppression struct {
	ID        string     `json:"id"`
	RuleID    string     `json:"rule_id"` // exact rule id, or "*" for any rule
	Field     string     `json:"field"`   // host|user|agent|summary|rule
	Op        string     `json:"op"`      // equals|contains
	Value     string     `json:"value"`
	Reason    string     `json:"reason,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Expires   *time.Time `json:"expires,omitempty"`
	Hits      int64      `json:"hits"` // detections suppressed by this rule
}

// RuleOverride enables/disables a detection rule fleet-wide from the console.
type RuleOverride struct {
	RuleID    string    `json:"rule_id"`
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Command is the message pushed to an agent over WebSocket.
type Command struct {
	ID     string         `json:"id"`
	Type   ResponseType   `json:"type"`
	Target map[string]any `json:"target"`
}

// CommandResult is the agent's reply for a command.
type CommandResult struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
