// Package model holds the wire types of the REST and WebSocket API. Field names mirror web/lib/types.ts.
package model

import "time"

type Role string

const (
	Admin   Role = "Admin"
	Analyst Role = "SecOps Analyst"
	Auditor Role = "Auditor"
)

type NodeHistory struct {
	T       int64   `json:"t"`
	RPS     float64 `json:"rps"`
	Latency float64 `json:"latency"`
	CPU     float64 `json:"cpu"`
}

type EdgeNode struct {
	ID                   string        `json:"id"`
	NodeName             string        `json:"node_name"`
	Hostname             string        `json:"hostname"`
	IPAddress            string        `json:"ip_address"`
	Proxy                string        `json:"proxy"`
	Version              string        `json:"version"`
	CRSVersion           string        `json:"crs_version"`
	Status               string        `json:"status"` // ONLINE | WARN | OFFLINE
	CurrentConfigVersion int64         `json:"current_config_version"`
	SyncStatus           string        `json:"sync_status"` // IN_SYNC | PENDING_UPDATE
	CPU                  float64       `json:"cpu"`
	Memory               float64       `json:"memory"`
	RPS                  float64       `json:"rps"`
	LatencyMs            float64       `json:"latency_ms"`
	LastHeartbeat        *time.Time    `json:"last_heartbeat"`
	Region               string        `json:"region"`
	Geo                  [2]float64    `json:"geo"`
	History              []NodeHistory `json:"history"`
}

type Site struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	DomainName        string          `json:"domain_name"`
	ParanoiaLevel     int             `json:"paranoia_level"`
	InboundThreshold  int             `json:"inbound_threshold"`
	OutboundThreshold int             `json:"outbound_threshold"`
	CRSCategories     map[string]bool `json:"crs_categories"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type CustomRule struct {
	ID         string    `json:"id"`
	RuleID     int       `json:"rule_id"`
	SiteID     *string   `json:"site_id"`
	Name       string    `json:"name"`
	SecLangRaw string    `json:"seclang_raw"`
	IsActive   bool      `json:"is_active"`
	CreatedBy  string    `json:"created_by"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type RuleException struct {
	ID              string    `json:"id"`
	SiteID          string    `json:"site_id"`
	RuleID          int       `json:"rule_id"`
	PathPattern     string    `json:"path_pattern"`
	ParameterName   *string   `json:"parameter_name"`
	Reason          string    `json:"reason"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	ExceptionRuleID int       `json:"-"`
}

type AuditLog struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	TransactionID   string            `json:"transaction_id"`
	NodeID          string            `json:"node_id"`
	SiteID          string            `json:"site_id"`
	Host            string            `json:"host"`
	ClientIP        string            `json:"client_ip"`
	ClientPort      uint16            `json:"client_port"`
	CountryCode     string            `json:"country_code"`
	ASN             uint32            `json:"asn"`
	HTTPMethod      string            `json:"http_method"`
	URI             string            `json:"uri"`
	HTTPVersion     string            `json:"http_version"`
	ResponseStatus  uint16            `json:"response_status"`
	ActionTaken     string            `json:"action_taken"`
	MatchedRuleIDs  []uint32          `json:"matched_rule_ids"`
	MatchedMessages []string          `json:"matched_messages"`
	MatchedData     []string          `json:"matched_data"`
	MatchedVars     []string          `json:"matched_vars"`
	Severity        string            `json:"severity"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	LatencyUs       uint64            `json:"latency_us"`
	CampaignID      string            `json:"campaign_id,omitempty"`
}

type AttackEvent struct {
	ID             string     `json:"id"`
	Timestamp      int64      `json:"timestamp"` // epoch ms
	TransactionID  string     `json:"transaction_id"`
	CampaignID     string     `json:"campaign_id"`
	NodeID         string     `json:"node_id"`
	SiteID         string     `json:"site_id"`
	Host           string     `json:"host"`
	ClientIP       string     `json:"client_ip"`
	CountryCode    string     `json:"country_code"`
	ASN            uint32     `json:"asn"`
	Geo            [2]float64 `json:"geo"`
	Method         string     `json:"method"`
	URI            string     `json:"uri"`
	RuleID         uint32     `json:"rule_id"`
	RuleCategory   string     `json:"rule_category"`
	KillchainStage string     `json:"killchain_stage"`
	Severity       string     `json:"severity"`
	Outcome        string     `json:"outcome"`
	ResponseStatus uint16     `json:"response_status"`
}

type Note struct {
	Author string `json:"author"`
	At     int64  `json:"at"`
	Text   string `json:"text"`
}

type Campaign struct {
	ID                    string     `json:"id"`
	ActorKey              string     `json:"actor_key"`
	ActorMode             string     `json:"actor_mode"`
	CountryCode           string     `json:"country_code"`
	ASN                   uint32     `json:"asn"`
	ASName                string     `json:"as_name"`
	Geo                   [2]float64 `json:"geo"`
	CorrelationConfidence string     `json:"correlation_confidence"`
	FirstSeen             int64      `json:"first_seen"`
	LastSeen              int64      `json:"last_seen"`
	HighestStage          string     `json:"highest_stage"`
	Stages                []string   `json:"stages"`
	RiskScore             int        `json:"risk_score"`
	EventCount            int64      `json:"event_count"`
	Status                string     `json:"status"`
	Assignee              *string    `json:"assignee"`
	Notes                 []Note     `json:"notes"`
	Targets               []string   `json:"targets"`
	PossiblySuccessful    int64      `json:"possibly_successful"`

	// Correlation state, not part of the API.
	SiteID     string   `json:"-"`
	Categories []string `json:"-"`
	ShellPaths []string `json:"-"`
	Opened     bool     `json:"-"`
}

type IPListEntry struct {
	ID        string     `json:"id"`
	CIDR      string     `json:"cidr"`
	List      string     `json:"list"`
	Source    string     `json:"source"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

type ThreatFeed struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Format          string     `json:"format"`
	IntervalMinutes int        `json:"interval_minutes"`
	LastPulled      *time.Time `json:"last_pulled"`
	Entries         int        `json:"entries"`
	Status          string     `json:"status"`
	Error           *string    `json:"error,omitempty"`
}

type AuditTrailEntry struct {
	ID          string    `json:"id"`
	At          time.Time `json:"at"`
	Actor       string    `json:"actor"`
	Role        Role      `json:"role"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	SourceIP    string    `json:"source_ip"`
	TargetNodes string    `json:"target_nodes"`
}

type User struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	Role      Role       `json:"role"`
	MFA       bool       `json:"mfa"`
	LastLogin *time.Time `json:"last_login"`
}

type KillchainMapping struct {
	ID             string  `json:"id"`
	RuleIDFrom     int     `json:"rule_id_from"`
	RuleIDTo       int     `json:"rule_id_to"`
	Tag            *string `json:"tag"`
	RuleCategory   string  `json:"rule_category"`
	KillchainStage string  `json:"killchain_stage"`
	MitreTechnique *string `json:"mitre_technique"`
}

type CorrelationSettings struct {
	SiteID             string `json:"site_id"`
	ActorKeyMode       string `json:"actor_key_mode"`
	IdleTimeoutMinutes int    `json:"idle_timeout_minutes"`
	MinEventsToOpen    int    `json:"min_events_to_open"`
}

// StreamMsg is one WebSocket /ws/attacks frame.
type StreamMsg struct {
	Event         AttackEvent `json:"event"`
	Log           AuditLog    `json:"log"`
	Campaign      Campaign    `json:"campaign"`
	IsNewCampaign bool        `json:"isNewCampaign"`
	EscalatedTo   *string     `json:"escalatedTo"`
}

// Bundle is a compiled, deployable configuration (stored in config_versions, pushed to nodes).
type Bundle struct {
	Version           int64             `json:"version"`
	DefaultDirectives string            `json:"default_directives"`
	SiteDirectives    map[string]string `json:"site_directives"` // host -> SecLang
	SiteIDs           map[string]string `json:"site_ids"`        // host -> site id
	BlockCIDRs        []string          `json:"block_cidrs"`
	AllowCIDRs        []string          `json:"allow_cidrs"`
}
