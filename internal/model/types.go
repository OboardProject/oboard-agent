package model

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type Protocol string

const (
	ProtocolVLESS  Protocol = "vless"
	ProtocolHY2    Protocol = "hy2"
	ProtocolAnyTLS Protocol = "anytls"
	ProtocolSS     Protocol = "shadowsocks"
	ProtocolMieru  Protocol = "mieru"
	ProtocolSocks  Protocol = "socks"
	ProtocolSSH    Protocol = "ssh"
)

type ServerStatus string

const (
	ServerUnknown  ServerStatus = "unknown"
	ServerOnline   ServerStatus = "online"
	ServerOffline  ServerStatus = "offline"
	ServerDegraded ServerStatus = "degraded"
)

type EntryIPMode string

const (
	EntryIPModeAuto   EntryIPMode = "auto"
	EntryIPModeIPv4   EntryIPMode = "ipv4"
	EntryIPModeIPv6   EntryIPMode = "ipv6"
	EntryIPModeCustom EntryIPMode = "custom"
)

type IPStack string

const (
	IPStackAuto       IPStack = "auto"
	IPStackIPv4Only   IPStack = "ipv4_only"
	IPStackIPv6Only   IPStack = "ipv6_only"
	IPStackDualStack  IPStack = "dual_stack"
	IPStackPreferIPv4 IPStack = "prefer_ipv4"
	IPStackPreferIPv6 IPStack = "prefer_ipv6"
)

type UDPInboundMode string

const (
	UDPInboundAllow UDPInboundMode = "allow"
	UDPInboundBlock UDPInboundMode = "block"
	UDPInboundUoT   UDPInboundMode = "uot"
)

type DNSTransport string

const (
	DNSTransportUDP DNSTransport = "udp"
	DNSTransportTCP DNSTransport = "tcp"
	DNSTransportDoT DNSTransport = "dot"
	DNSTransportDoH DNSTransport = "doh"
	DNSTransportDoQ DNSTransport = "doq"
)

type DNSAutoTestMode string

const (
	DNSAutoTestNever      DNSAutoTestMode = "never"
	DNSAutoTestFirstApply DNSAutoTestMode = "first_apply"
	DNSAutoTestPeriodic   DNSAutoTestMode = "periodic"
	DNSAutoTestAlways     DNSAutoTestMode = "always"
)

type MTUMode string

const (
	MTUModeDisabled MTUMode = "disabled"
	MTUModeDetect   MTUMode = "detect"
	MTUModeApply    MTUMode = "apply"
)

type TimeCorrectionMode string

const (
	TimeCorrectionOff  TimeCorrectionMode = "off"
	TimeCorrectionAuto TimeCorrectionMode = "auto"
	TimeCorrectionNTP  TimeCorrectionMode = "ntp"
)

type RouteAction string

const (
	RouteActionDirect   RouteAction = "direct"
	RouteActionBlock    RouteAction = "block"
	RouteActionOutbound RouteAction = "outbound"
	RouteActionExternal RouteAction = "external"
)

type ExternalOutboundScope string

const (
	ExternalOutboundScopeGlobal ExternalOutboundScope = "global"
	ExternalOutboundScopeServer ExternalOutboundScope = "server"
)

type WARPStatus string

const (
	WARPStatusNeeded    WARPStatus = "needed"
	WARPStatusRequested WARPStatus = "requested"
	WARPStatusReady     WARPStatus = "ready"
	WARPStatusFailed    WARPStatus = "failed"
)

type User struct {
	ID                int64     `json:"id"`
	Username          string    `json:"username"`
	PasswordHash      string    `json:"-"`
	Role              Role      `json:"role"`
	Status            string    `json:"status"`
	ProxyUUID         string    `json:"proxy_uuid"`
	ProxyPassword     string    `json:"proxy_password"`
	SpeedLimitMbps    int       `json:"speed_limit_mbps"`
	TrafficLimitBytes int64     `json:"traffic_limit_bytes"`
	TrafficUsedBytes  int64     `json:"traffic_used_bytes"`
	TrafficResetMode  string    `json:"traffic_reset_mode"`
	TrafficResetDay   int       `json:"traffic_reset_day"`
	TrafficPeriodKey  string    `json:"traffic_period_key,omitempty"`
	TrafficPeriodEnd  string    `json:"traffic_period_end,omitempty"`
	TrafficQuotaState string    `json:"traffic_quota_state,omitempty"`
	SubscriptionToken string    `json:"subscription_token,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type SubscriptionFormat string

const (
	SubscriptionFormatStash        SubscriptionFormat = "stash"
	SubscriptionFormatClashMeta    SubscriptionFormat = "clash-meta"
	SubscriptionFormatMihomo       SubscriptionFormat = "mihomo"
	SubscriptionFormatSurfboard    SubscriptionFormat = "surfboard"
	SubscriptionFormatSurge        SubscriptionFormat = "surge"
	SubscriptionFormatSurgeMac     SubscriptionFormat = "surge-mac"
	SubscriptionFormatLoon         SubscriptionFormat = "loon"
	SubscriptionFormatEgern        SubscriptionFormat = "egern"
	SubscriptionFormatShadowrocket SubscriptionFormat = "shadowrocket"
	SubscriptionFormatQX           SubscriptionFormat = "qx"
	SubscriptionFormatSingBox      SubscriptionFormat = "sing-box"
	SubscriptionFormatV2Ray        SubscriptionFormat = "v2ray"
	SubscriptionFormatV2RayURI     SubscriptionFormat = "v2ray-uri"
	SubscriptionFormatClash        SubscriptionFormat = "clash"
)

type SubscriptionProfile struct {
	ID          int64              `json:"id"`
	Name        string             `json:"name"`
	Format      SubscriptionFormat `json:"format"`
	GroupName   string             `json:"group_name"`
	Description string             `json:"description"`
	ConfigJSON  string             `json:"config_json"`
	Enabled     bool               `json:"enabled"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type SubscriptionAssignment struct {
	ID        int64     `json:"id"`
	ProfileID int64     `json:"profile_id"`
	UserID    int64     `json:"user_id"`
	ServerID  *int64    `json:"server_id,omitempty"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	GroupName string    `json:"group_name"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Server struct {
	ID               int64          `json:"id"`
	Name             string         `json:"name"`
	AgentID          string         `json:"agent_id"`
	AgentTokenHash   string         `json:"-"`
	EnrollmentHash   string         `json:"-"`
	PublicIPv4       string         `json:"public_ipv4"`
	PublicIPv6       string         `json:"public_ipv6"`
	EntryIPMode      EntryIPMode    `json:"entry_ip_mode"`
	ListenIP         string         `json:"listen_ip"`
	IPStack          IPStack        `json:"ip_stack"`
	UDPInboundMode   UDPInboundMode `json:"udp_inbound_mode"`
	MTUMode          MTUMode        `json:"mtu_mode"`
	MTUValue         int            `json:"mtu_value"`
	MTUProbeHost     string         `json:"mtu_probe_host"`
	MTUProbePort     int            `json:"mtu_probe_port"`
	MTUOverheadBytes int            `json:"mtu_overhead_bytes"`
	PortRangeStart   int            `json:"port_range_start"`
	PortRangeEnd     int            `json:"port_range_end"`
	Status           ServerStatus   `json:"status"`
	OS               string         `json:"os"`
	DistroID         string         `json:"distro_id"`
	DistroVersion    string         `json:"distro_version"`
	DistroName       string         `json:"distro_name"`
	Libc             string         `json:"libc"`
	ServiceManager   string         `json:"service_manager"`
	PackageManager   string         `json:"package_manager"`
	Arch             string         `json:"arch"`
	Kernel           string         `json:"kernel"`
	CPU              string         `json:"cpu"`
	MemoryBytes      uint64         `json:"memory_bytes"`
	CPUUsagePercent  float64        `json:"cpu_usage_percent"`
	MemoryUsedBytes  uint64         `json:"memory_used_bytes"`
	MemoryTotalBytes uint64         `json:"memory_total_bytes"`
	AgentMemoryBytes uint64         `json:"agent_memory_bytes"`
	DiskBytes        uint64         `json:"disk_bytes"`
	AgentVersion     string         `json:"agent_version"`
	AgentBuild       string         `json:"agent_build"`
	SingBoxVersion   string         `json:"sing_box_version"`
	LastSeenAt       *time.Time     `json:"last_seen_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type Inbound struct {
	ID              int64       `json:"id"`
	ServerID        int64       `json:"server_id"`
	Name            string      `json:"name"`
	Protocol        Protocol    `json:"protocol"`
	ListenIP        string      `json:"listen_ip"`
	Port            int         `json:"port"`
	EntryIPMode     EntryIPMode `json:"entry_ip_mode"`
	ExternalIP      string      `json:"external_ip"`
	DNSSyncEnabled  bool        `json:"dns_sync_enabled"`
	DNSCredentialID *int64      `json:"dns_credential_id,omitempty"`
	DNSDomain       string      `json:"dns_domain"`
	DNSProxyEnabled bool        `json:"dns_proxy_enabled"`
	DNSRecordTypes  string      `json:"dns_record_types"`
	TLS             bool        `json:"tls"`
	ConfigJSON      string      `json:"config_json"`
	Enabled         bool        `json:"enabled"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

const (
	CertificateModeExternal = "external"
	CertificateModeAuto     = "auto"
	CertificateModeExact    = "exact"
	CertificateModeWildcard = "wildcard"
	CertificateModeExplicit = "explicit"
)

const (
	CertificateChallengeHTTP      = "http01"
	CertificateChallengeDNS       = "dns01"
	CertificateChallengeDNSManual = "dns01_manual"
)

const (
	CertificateStatusPending     = "pending"
	CertificateStatusIssuing     = "issuing"
	CertificateStatusAwaitingDNS = "awaiting_dns"
	CertificateStatusReady       = "ready"
	CertificateStatusFailed      = "failed"
)

type InboundUser struct {
	ID        int64     `json:"id"`
	InboundID int64     `json:"inbound_id"`
	UserID    int64     `json:"user_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AccessSubjectType string

const (
	AccessSubjectUser  AccessSubjectType = "user"
	AccessSubjectGroup AccessSubjectType = "group"
)

type AccessScopeType string

const (
	AccessScopeGlobal  AccessScopeType = "global"
	AccessScopeServer  AccessScopeType = "server"
	AccessScopeInbound AccessScopeType = "inbound"
)

type UserGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UserGroupMember struct {
	ID        int64     `json:"id"`
	GroupID   int64     `json:"group_id"`
	UserID    int64     `json:"user_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type InboundAccessGrant struct {
	ID          int64             `json:"id"`
	SubjectType AccessSubjectType `json:"subject_type"`
	SubjectID   int64             `json:"subject_id"`
	ScopeType   AccessScopeType   `json:"scope_type"`
	ServerID    *int64            `json:"server_id,omitempty"`
	InboundID   *int64            `json:"inbound_id,omitempty"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Outbound struct {
	ID            int64     `json:"id"`
	ServerID      int64     `json:"server_id"`
	NextServerID  *int64    `json:"next_server_id,omitempty"`
	Name          string    `json:"name"`
	Protocol      Protocol  `json:"protocol"`
	TargetAddress string    `json:"target_address"`
	TargetPort    int       `json:"target_port"`
	ConfigJSON    string    `json:"config_json"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RoutingRule struct {
	ID                 int64       `json:"id"`
	ServerID           int64       `json:"server_id"`
	Name               string      `json:"name"`
	Priority           int         `json:"priority"`
	MatchJSON          string      `json:"match_json"`
	Action             RouteAction `json:"action"`
	OutboundID         *int64      `json:"outbound_id,omitempty"`
	ExternalOutboundID *int64      `json:"external_outbound_id,omitempty"`
	TargetServerID     *int64      `json:"target_server_id,omitempty"`
	OutboundTag        string      `json:"outbound_tag"`
	Enabled            bool        `json:"enabled"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

type ExternalOutbound struct {
	ID            int64                 `json:"id"`
	ServerID      *int64                `json:"server_id,omitempty"`
	Name          string                `json:"name"`
	Protocol      Protocol              `json:"protocol"`
	Scope         ExternalOutboundScope `json:"scope"`
	TargetAddress string                `json:"target_address"`
	TargetPort    int                   `json:"target_port"`
	ConfigJSON    string                `json:"config_json"`
	ExposeToUsers bool                  `json:"expose_to_users"`
	Enabled       bool                  `json:"enabled"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type ExternalOutboundAccessGrant struct {
	ID                 int64             `json:"id"`
	ExternalOutboundID int64             `json:"external_outbound_id"`
	SubjectType        AccessSubjectType `json:"subject_type"`
	SubjectID          int64             `json:"subject_id"`
	Enabled            bool              `json:"enabled"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

type ProxyPath struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	InboundID int64     `json:"inbound_id"`
	Secret    string    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProxyPathStepNodeType string

const (
	ProxyPathStepServerInbound ProxyPathStepNodeType = "server_inbound"
	ProxyPathStepImported      ProxyPathStepNodeType = "imported"
	ProxyPathStepWARP          ProxyPathStepNodeType = "warp"
)

type ProxyPathStepTransportMode string

const (
	ProxyPathTransportSingBox     ProxyPathStepTransportMode = "singbox"
	ProxyPathTransportPortForward ProxyPathStepTransportMode = "port_forward"
	ProxyPathTransportTunnel      ProxyPathStepTransportMode = "tunnel"
)

type ProxyPathPlanStep struct {
	ID                 int64                      `json:"id"`
	Position           int                        `json:"position"`
	NodeType           ProxyPathStepNodeType      `json:"node_type"`
	TransportMode      ProxyPathStepTransportMode `json:"transport_mode"`
	ProcessingRole     bool                       `json:"processing_role"`
	ServerID           *int64                     `json:"server_id,omitempty"`
	InboundID          *int64                     `json:"inbound_id,omitempty"`
	ExternalOutboundID *int64                     `json:"external_outbound_id,omitempty"`
	TunnelID           int64                      `json:"tunnel_id,omitempty"`
}

type ProxyPathPlan struct {
	PathID       int64               `json:"path_id"`
	Name         string              `json:"name"`
	InboundID    int64               `json:"inbound_id"`
	Enabled      bool                `json:"enabled"`
	Steps        []ProxyPathPlanStep `json:"steps"`
	Warnings     []string            `json:"warnings,omitempty"`
	PortForwards []PortForward       `json:"port_forwards,omitempty"`
	Tunnels      []Tunnel            `json:"tunnels,omitempty"`
}

type ProxyPathStep struct {
	ID                 int64                      `json:"id"`
	PathID             int64                      `json:"path_id"`
	Position           int                        `json:"position"`
	NodeType           ProxyPathStepNodeType      `json:"node_type"`
	TransportMode      ProxyPathStepTransportMode `json:"transport_mode"`
	ProcessingRole     bool                       `json:"processing_role"`
	ServerID           *int64                     `json:"server_id,omitempty"`
	InboundID          *int64                     `json:"inbound_id,omitempty"`
	ExternalOutboundID *int64                     `json:"external_outbound_id,omitempty"`
	ConfigJSON         string                     `json:"config_json"`
	CreatedAt          time.Time                  `json:"created_at"`
	UpdatedAt          time.Time                  `json:"updated_at"`
}

type WARPProfile struct {
	ID              int64      `json:"id"`
	ServerID        int64      `json:"server_id"`
	Name            string     `json:"name"`
	Status          WARPStatus `json:"status"`
	ConfigJSON      string     `json:"config_json"`
	MTU             int        `json:"mtu"`
	DNSStrategy     string     `json:"dns_strategy"`
	LastRequestedAt *time.Time `json:"last_requested_at,omitempty"`
	Error           string     `json:"error"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type DNSCandidate struct {
	Tag       string       `json:"tag"`
	Transport DNSTransport `json:"transport"`
	Server    string       `json:"server"`
	Port      int          `json:"port"`
	Path      string       `json:"path,omitempty"`
	TLSName   string       `json:"tls_name,omitempty"`
}

type DNSBenchmarkPlan struct {
	Version               int64           `json:"version"`
	ServerID              int64           `json:"server_id"`
	PolicyRevision        int64           `json:"policy_revision"`
	EncryptedListID       int64           `json:"encrypted_list_id"`
	EncryptedListRevision int64           `json:"encrypted_list_revision"`
	BootstrapListID       int64           `json:"bootstrap_list_id"`
	BootstrapListRevision int64           `json:"bootstrap_list_revision"`
	Mode                  DNSAutoTestMode `json:"mode"`
	IntervalSeconds       int             `json:"interval_seconds"`
	RequestID             string          `json:"request_id,omitempty"`
	EncryptedCandidates   []DNSCandidate  `json:"encrypted_candidates"`
	BootstrapCandidates   []DNSCandidate  `json:"bootstrap_candidates"`
}

type WARPRequestPlan struct {
	Version     int64   `json:"version"`
	ServerID    int64   `json:"server_id"`
	ProfileID   int64   `json:"profile_id"`
	OutboundTag string  `json:"outbound_tag"`
	IPStack     IPStack `json:"ip_stack"`
	MTU         int     `json:"mtu"`
	DNSStrategy string  `json:"dns_strategy"`
}

type WARPConfigReport struct {
	ServerID   int64      `json:"server_id"`
	ProfileID  int64      `json:"profile_id"`
	Status     WARPStatus `json:"status"`
	ConfigJSON string     `json:"config_json"`
	MTU        int        `json:"mtu"`
	Error      string     `json:"error"`
	ResultJSON string     `json:"result_json"`
}

type DNSBenchmarkResult struct {
	ID                    int64             `json:"id"`
	ReportID              string            `json:"report_id"`
	RequestID             string            `json:"request_id,omitempty"`
	ServerID              int64             `json:"server_id"`
	PolicyRevision        int64             `json:"policy_revision"`
	EncryptedListID       int64             `json:"encrypted_list_id"`
	EncryptedListRevision int64             `json:"encrypted_list_revision"`
	BootstrapListID       int64             `json:"bootstrap_list_id"`
	BootstrapListRevision int64             `json:"bootstrap_list_revision"`
	Encrypted             DNSBenchmarkGroup `json:"encrypted"`
	Bootstrap             DNSBenchmarkGroup `json:"bootstrap"`
	Status                string            `json:"status"`
	Error                 string            `json:"error"`
	CreatedAt             time.Time         `json:"created_at"`
}

type DNSBenchmarkItem struct {
	Tag       string `json:"tag"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type DNSBenchmarkGroup struct {
	Items    []DNSBenchmarkItem `json:"items"`
	BestTags []string           `json:"best_tags"`
}

type MTUDetectionMethod struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	MTU       int    `json:"mtu"`
	LatencyMS int64  `json:"latency_ms"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
}

type MTUDetectionPlan struct {
	Version       int64   `json:"version"`
	ServerID      int64   `json:"server_id"`
	Mode          MTUMode `json:"mode"`
	TargetHost    string  `json:"target_host"`
	TargetPort    int     `json:"target_port"`
	InterfaceName string  `json:"interface_name,omitempty"`
	OverheadBytes int     `json:"overhead_bytes"`
	DesiredMTU    int     `json:"desired_mtu"`
	SampleCount   int     `json:"sample_count"`
	TimeoutMS     int     `json:"timeout_ms"`
	MinMTU        int     `json:"min_mtu"`
	MaxMTU        int     `json:"max_mtu"`
}

type MTUDetectionResult struct {
	ID             int64                `json:"id"`
	ServerID       int64                `json:"server_id"`
	Mode           MTUMode              `json:"mode"`
	TargetHost     string               `json:"target_host"`
	TargetPort     int                  `json:"target_port"`
	InterfaceName  string               `json:"interface_name"`
	CurrentMTU     int                  `json:"current_mtu"`
	PathMTU        int                  `json:"path_mtu"`
	RecommendedMTU int                  `json:"recommended_mtu"`
	AppliedMTU     int                  `json:"applied_mtu"`
	Confidence     string               `json:"confidence"`
	Methods        []MTUDetectionMethod `json:"methods,omitempty"`
	Error          string               `json:"error"`
	ResultJSON     string               `json:"result_json"`
	CreatedAt      time.Time            `json:"created_at"`
}

type ForwardBackend string

const (
	ForwardBackendAuto    ForwardBackend = "auto"
	ForwardBackendRealm   ForwardBackend = "realm"
	ForwardBackendNFT     ForwardBackend = "nft"
	ForwardBackendBuiltin ForwardBackend = "builtin"
)

type ForwardProtocol string

const (
	ForwardProtocolTCP    ForwardProtocol = "tcp"
	ForwardProtocolUDP    ForwardProtocol = "udp"
	ForwardProtocolTCPUDP ForwardProtocol = "tcp_udp"
)

type PortForward struct {
	ID                   int64                 `json:"id"`
	Name                 string                `json:"name"`
	SourceServerID       int64                 `json:"source_server_id"`
	TargetServerID       int64                 `json:"target_server_id"`
	ListenIP             string                `json:"listen_ip"`
	ListenPort           int                   `json:"listen_port"`
	TargetAddress        string                `json:"target_address"`
	TargetPort           int                   `json:"target_port"`
	Protocol             ForwardProtocol       `json:"protocol"`
	Backend              ForwardBackend        `json:"backend"`
	ProbeMode            string                `json:"probe_mode"`
	ProbeIntervalSeconds int                   `json:"probe_interval_seconds"`
	SampleRate           float64               `json:"sample_rate"`
	Priority             int                   `json:"priority"`
	ConfigJSON           string                `json:"config_json"`
	TrustedForward       *TrustedForwardSender `json:"trusted_forward,omitempty"`
	Enabled              bool                  `json:"enabled"`
	CreatedAt            time.Time             `json:"created_at"`
	UpdatedAt            time.Time             `json:"updated_at"`
}

type TrustedForwardSender struct {
	Version             int    `json:"version"`
	ReceiverID          string `json:"receiver_id"`
	Key                 string `json:"key"`
	MaxClockSkewSeconds int    `json:"max_clock_skew_seconds"`
}

type TunnelType string

const (
	TunnelTypeWireGuard TunnelType = "wireguard"
	TunnelTypeSSH       TunnelType = "ssh"
)

type Tunnel struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	SourceServerID int64      `json:"source_server_id"`
	TargetServerID int64      `json:"target_server_id"`
	Type           TunnelType `json:"type"`
	LocalAddress   string     `json:"local_address"`
	PeerAddress    string     `json:"peer_address"`
	ListenPort     int        `json:"listen_port"`
	TargetEndpoint string     `json:"target_endpoint"`
	TargetPort     int        `json:"target_port"`
	Priority       int        `json:"priority"`
	ConfigJSON     string     `json:"config_json"`
	Enabled        bool       `json:"enabled"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type TunnelPlan struct {
	Version int64    `json:"version"`
	Tunnels []Tunnel `json:"tunnels"`
}

type PortForwardProbeResult struct {
	ID            int64     `json:"id"`
	PortForwardID int64     `json:"port_forward_id"`
	ServerID      int64     `json:"server_id"`
	Mode          string    `json:"mode"`
	Available     bool      `json:"available"`
	LatencyMS     int64     `json:"latency_ms"`
	SampleCount   int       `json:"sample_count"`
	Error         string    `json:"error"`
	ResultJSON    string    `json:"result_json"`
	CreatedAt     time.Time `json:"created_at"`
}

type PortForwardPlan struct {
	Version int64         `json:"version"`
	Rules   []PortForward `json:"rules"`
}

// SSHInboundPlan configures OBoard's deliberately restricted SSH proxy
// listeners.  It is separate from the core configuration because it is
// implemented by the Agent, not sing-box.
type SSHInboundPlan struct {
	Version  int64        `json:"version"`
	Inbounds []SSHInbound `json:"inbounds"`
}

// SSHInbound accepts password-only SSH client authentication and permits
// direct-tcpip channels, including the fixed in-process BadVPN UDP gateway.
// Address is the panel-visible endpoint; the Agent listens on ListenIP:Port.
type SSHInbound struct {
	InboundID int64                           `json:"inbound_id"`
	ServerID  int64                           `json:"server_id"`
	Name      string                          `json:"name"`
	ListenIP  string                          `json:"listen_ip"`
	Address   string                          `json:"address"`
	Port      int                             `json:"port"`
	Enabled   bool                            `json:"enabled"`
	Users     []SSHInboundUser                `json:"users"`
	Policies  map[string]TrafficRuntimePolicy `json:"policies"`
}

// SSHInboundUser maps one panel user to an isolated SSH login. Shell access
// and agent forwarding are intentionally unsupported.
type SSHInboundUser struct {
	UserID           int64  `json:"user_id"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	DeviceIDHash     string `json:"device_id_hash,omitempty"`
	CredentialEpoch  int64  `json:"credential_epoch,omitempty"`
	CredentialStatus string `json:"credential_status,omitempty"`
	PathID           int64  `json:"path_id"`
	RouteKind        string `json:"route_kind"`
	OutboundTag      string `json:"outbound_tag,omitempty"`
	Enabled          bool   `json:"enabled"`
}

type AgentTask struct {
	ID            int64      `json:"id"`
	ServerID      int64      `json:"server_id"`
	Type          string     `json:"type"`
	PayloadJSON   string     `json:"payload_json"`
	Status        string     `json:"status"`
	ResultJSON    string     `json:"result_json"`
	ConfigVersion int64      `json:"config_version"`
	Nonce         string     `json:"nonce"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

const (
	AgentTaskTypeApplyDeployment       = "apply_deployment"
	AgentTaskTypeApplyCoreConfig       = "apply_core_config"
	AgentTaskTypeUpdateAgent           = "update_agent"
	AgentTaskTypeUpdateAgentConfig     = "update_agent_config"
	AgentTaskTypeDiagnoseNetwork       = "diagnose_network"
	AgentTaskTypeListNetworkInterfaces = "list_network_interfaces"
	AgentTaskTypeProbeInbounds         = "probe_inbounds"
	AgentTaskTypeProbePortForwards     = "probe_port_forwards"
	AgentTaskTypeProbeExternalEgress   = "probe_external_egress"
	AgentTaskTypeDetectMTU             = "detect_mtu"
	AgentTaskTypeBenchmarkDNS          = "benchmark_dns"
	AgentTaskTypeCollectLogs           = "collect_logs"
	AgentTaskTypeManageLogs            = "manage_logs"
	AgentTaskTypeCheckTime             = "check_time"
	AgentTaskTypeIssueCertificateHTTP  = "issue_certificate_http01"
)

type NetworkInterfaceInfo struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Running   bool     `json:"running"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}

type AgentEnrollRequest struct {
	EnrollmentToken string       `json:"enrollment_token"`
	Health          HealthReport `json:"health"`
}

type AgentEnrollResponse struct {
	ServerID               int64  `json:"server_id"`
	AgentID                string `json:"agent_id"`
	AgentToken             string `json:"agent_token"`
	ConnectionAuditEnabled bool   `json:"connection_audit_enabled"`
}

type AgentSocketMessage struct {
	Type         string          `json:"type"`
	ServerID     int64           `json:"server_id,omitempty"`
	Timestamp    time.Time       `json:"ts,omitempty"`
	Task         *AgentTask      `json:"task,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	HealthReport *HealthReport   `json:"health_report,omitempty"`
	Raw          json.RawMessage `json:"-"`
}

type AgentTaskResultReport struct {
	TaskID       int64         `json:"task_id"`
	Status       string        `json:"status"`
	ResultJSON   string        `json:"result_json"`
	HealthReport *HealthReport `json:"health_report,omitempty"`
}

type ApplyCoreConfigTaskPayload struct {
	Config       string                  `json:"config"`
	Reason       string                  `json:"reason,omitempty"`
	PrunedUserID int64                   `json:"pruned_user_id,omitempty"`
	Assets       []ManagedAssetReference `json:"assets,omitempty"`
}

// DeploymentTaskPayload keeps one user deployment as one Agent task while
// preserving the individual execution plans needed by the Agent.
type DeploymentTaskPayload struct {
	Version              int64                      `json:"version"`
	Config               ApplyCoreConfigTaskPayload `json:"config"`
	ConfigChanged        bool                       `json:"config_changed"`
	WARPRequests         []WARPRequestPlan          `json:"warp_requests,omitempty"`
	TimeCheck            *TimeCheckPlan             `json:"time_check,omitempty"`
	PortForwards         PortForwardPlan            `json:"port_forwards"`
	InboundProbe         *InboundProbePlan          `json:"inbound_probe,omitempty"`
	ExternalInboundProbe *InboundProbePlan          `json:"external_inbound_probe,omitempty"`
	PortForwardProbe     *PortForwardPlan           `json:"port_forward_probe,omitempty"`
	ExternalEgressProbe  *ExternalEgressProbePlan   `json:"external_egress_probe,omitempty"`
	Tunnels              TunnelPlan                 `json:"tunnels"`
	SSHInbounds          SSHInboundPlan             `json:"ssh_inbounds"`
	DNSBenchmark         *DNSBenchmarkPlan          `json:"dns_benchmark,omitempty"`
	MTUDetection         *MTUDetectionPlan          `json:"mtu_detection,omitempty"`
}

type ExternalEgressProbePlan struct {
	Version               int64                       `json:"version"`
	ExpectedConfigVersion int64                       `json:"expected_config_version,omitempty"`
	TimeoutMS             int                         `json:"timeout_ms"`
	Targets               []ExternalEgressProbeTarget `json:"targets"`
}

type ExternalEgressProbeTarget struct {
	ProbeID             string `json:"probe_id"`
	PathID              int64  `json:"path_id"`
	ExternalOutboundID  int64  `json:"external_outbound_id"`
	OwnerServerID       int64  `json:"owner_server_id"`
	OutboundTag         string `json:"outbound_tag"`
	TopologyFingerprint string `json:"topology_fingerprint"`
}

type ExternalEgressProbeItem struct {
	ProbeID string `json:"probe_id"`
	Status  string `json:"status"`
	ExitIP  string `json:"exit_ip,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ExternalEgressProbeResult struct {
	Items []ExternalEgressProbeItem `json:"items"`
}

type IssueCertificateHTTPTaskPayload struct {
	CertificateID int64    `json:"certificate_id"`
	Domains       []string `json:"domains"`
	AccountEmail  string   `json:"account_email"`
	ACMECA        string   `json:"acme_ca"`
	Renew         bool     `json:"renew"`
}

type ManagedAssetReference struct {
	Kind     string `json:"kind"`
	ID       int64  `json:"id"`
	Revision string `json:"revision"`
}

type ManagedAssetRequest struct {
	Assets []ManagedAssetReference `json:"assets"`
}

type ManagedAssetFile struct {
	Name       string `json:"name"`
	ContentB64 string `json:"content_b64"`
	Mode       uint32 `json:"mode"`
}

type ManagedAsset struct {
	ManagedAssetReference
	Files []ManagedAssetFile `json:"files"`
}

type ManagedAssetResponse struct {
	Assets []ManagedAsset `json:"assets"`
}

type CertificateIssueReport struct {
	TaskID         int64    `json:"task_id"`
	CertificateID  int64    `json:"certificate_id"`
	Domains        []string `json:"domains"`
	CertificatePEM string   `json:"certificate_pem"`
	FullchainPEM   string   `json:"fullchain_pem"`
	PrivateKeyPEM  string   `json:"private_key_pem"`
}

type UpdateAgentTaskPayload struct {
	ControllerURL string `json:"controller_url"`
	ExpectedBuild string `json:"expected_build"`
	Source        string `json:"source"`
	GitHubRepo    string `json:"github_repo"`
}

type AgentUpdateRequest struct {
	Source     string `json:"source"`
	GitHubRepo string `json:"github_repo"`
}

type AgentConfigPatch struct {
	ControllerURL         string             `json:"controller_url,omitempty"`
	StateDir              string             `json:"state_dir,omitempty"`
	CoreBinary            string             `json:"core_binary,omitempty"`
	CoreService           string             `json:"core_service,omitempty"`
	CommandTimeoutSeconds int                `json:"command_timeout_seconds,omitempty"`
	ReloadCommand         string             `json:"reload_command,omitempty"`
	RestartCommand        string             `json:"restart_command,omitempty"`
	TimeSyncCommand       string             `json:"time_sync_command,omitempty"`
	TimeCorrectionMode    TimeCorrectionMode `json:"time_correction_mode,omitempty"`
	LogMaxMB              int                `json:"log_max_mb,omitempty"`
	LogBackups            int                `json:"log_backups,omitempty"`
	CoreLogMaxMB          int                `json:"core_log_max_mb,omitempty"`
	CoreLogBackups        int                `json:"core_log_backups,omitempty"`
	UpdateSource          string             `json:"update_source,omitempty"`
	AllowPanelUpdate      bool               `json:"allow_panel_update,omitempty"`
	UpdateRepo            string             `json:"update_repo,omitempty"`
}

type DiagnosticTarget struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
}

type DiagnoseNetworkTaskPayload struct {
	Version      int64              `json:"version"`
	ServerID     int64              `json:"server_id"`
	EntryTargets []DiagnosticTarget `json:"entry_targets"`
}

type InboundProbeTarget struct {
	InboundID   int64    `json:"inbound_id"`
	Name        string   `json:"name"`
	Protocol    Protocol `json:"protocol"`
	Host        string   `json:"host"`
	ListenIP    string   `json:"listen_ip"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	SampleCount int      `json:"sample_count,omitempty"`
}

type InboundProbePlan struct {
	Version      int64                `json:"version"`
	ServerID     int64                `json:"server_id"`
	SampleCount  int                  `json:"sample_count"`
	IntervalMS   int                  `json:"interval_ms"`
	TimeoutMS    int                  `json:"timeout_ms"`
	EntryTargets []InboundProbeTarget `json:"entry_targets"`
}

type InboundProbeResult struct {
	ID            int64     `json:"id"`
	InboundID     int64     `json:"inbound_id"`
	ServerID      int64     `json:"server_id"`
	ConfigVersion int64     `json:"config_version"`
	Mode          string    `json:"mode"`
	Transport     string    `json:"transport"`
	Endpoint      string    `json:"endpoint"`
	Available     bool      `json:"available"`
	Confirmed     bool      `json:"confirmed"`
	LatencyMS     int64     `json:"latency_ms"`
	MinLatencyMS  int64     `json:"min_latency_ms"`
	P95LatencyMS  int64     `json:"p95_latency_ms"`
	JitterMS      int64     `json:"jitter_ms"`
	SampleCount   int       `json:"sample_count"`
	SuccessCount  int       `json:"success_count"`
	Error         string    `json:"error"`
	ResultJSON    string    `json:"result_json"`
	CreatedAt     time.Time `json:"created_at"`
}

type CollectLogsTaskPayload struct {
	Lines    int    `json:"lines"`
	Services string `json:"services"`
}

type ManageLogsTaskPayload struct {
	Action   string `json:"action"`
	Services string `json:"services"`
}

type TimeCheckPlan struct {
	Version          int64              `json:"version"`
	CorrectionMode   TimeCorrectionMode `json:"correction_mode"`
	ThresholdSeconds int                `json:"threshold_seconds"`
	NTPServers       []string           `json:"ntp_servers"`
	Force            bool               `json:"force,omitempty"`
}

type TimeCheckResult struct {
	Status               string             `json:"status"`
	CorrectionMode       TimeCorrectionMode `json:"correction_mode"`
	RawOffsetMS          int64              `json:"raw_offset_ms"`
	EffectiveOffsetMS    int64              `json:"effective_offset_ms"`
	Source               string             `json:"source"`
	CheckedAt            time.Time          `json:"checked_at"`
	SystemSyncAttempted  bool               `json:"system_sync_attempted"`
	SystemSyncSucceeded  bool               `json:"system_sync_succeeded"`
	SystemSyncError      string             `json:"system_sync_error,omitempty"`
	LogicalTimeActive    bool               `json:"logical_time_active"`
	UnsupportedTimePaths []string           `json:"unsupported_time_paths,omitempty"`
	Error                string             `json:"error,omitempty"`
}

type NotificationChannel struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Enabled    bool      `json:"enabled"`
	Events     string    `json:"events"`
	ConfigJSON string    `json:"config_json"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	ActorID   *int64    `json:"actor_id,omitempty"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

type TrafficStat struct {
	ID        int64     `json:"id"`
	ServerID  int64     `json:"server_id"`
	UserID    *int64    `json:"user_id,omitempty"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

type TrafficPeriod struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	PeriodKey string    `json:"period_key"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	Limit     int64     `json:"traffic_limit_bytes"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TrafficReport struct {
	ReportID  string    `json:"report_id"`
	ServerID  int64     `json:"server_id"`
	UserID    int64     `json:"user_id"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	PathID    *int64    `json:"path_id,omitempty"`
	PeriodKey string    `json:"period_key"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

type TrafficRuntimePolicy struct {
	UserID            int64  `json:"user_id"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	CredentialStatus  string `json:"credential_status,omitempty"`
	Billable          bool   `json:"billable"`
	SpeedLimitMbps    int    `json:"speed_limit_mbps,omitempty"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes,omitempty"`
	UsedBaselineBytes int64  `json:"used_baseline_bytes,omitempty"`
	LeaseBytes        int64  `json:"lease_bytes,omitempty"`
	ResetLeaseBytes   int64  `json:"reset_lease_bytes,omitempty"`
	LeaseEnforced     bool   `json:"lease_enforced,omitempty"`
	PeriodKey         string `json:"period_key,omitempty"`
	PeriodStart       string `json:"period_start,omitempty"`
	PeriodEnd         string `json:"period_end,omitempty"`
	ResetMode         string `json:"reset_mode,omitempty"`
	ResetDay          int    `json:"reset_day,omitempty"`
	ResetAnchor       string `json:"reset_anchor,omitempty"`
	PreviousPeriodKey string `json:"previous_period_key,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	QuotaState        string `json:"quota_state,omitempty"`
	EnforcementMode   string `json:"enforcement_mode,omitempty"`
}

type HealthReport struct {
	AgentID                   string       `json:"agent_id"`
	Status                    ServerStatus `json:"status"`
	PublicIPv4                string       `json:"public_ipv4"`
	PublicIPv6                string       `json:"public_ipv6"`
	InterfaceIPv6             string       `json:"interface_ipv6"`
	RegionCode                string       `json:"region_code"`
	OS                        string       `json:"os"`
	DistroID                  string       `json:"distro_id"`
	DistroVersion             string       `json:"distro_version"`
	DistroName                string       `json:"distro_name"`
	Libc                      string       `json:"libc"`
	ServiceManager            string       `json:"service_manager"`
	PackageManager            string       `json:"package_manager"`
	Arch                      string       `json:"arch"`
	Kernel                    string       `json:"kernel"`
	CPU                       string       `json:"cpu"`
	MemoryBytes               uint64       `json:"memory_bytes"`
	CPUUsagePercent           float64      `json:"cpu_usage_percent"`
	MemoryUsedBytes           uint64       `json:"memory_used_bytes"`
	MemoryTotalBytes          uint64       `json:"memory_total_bytes"`
	AgentMemoryBytes          uint64       `json:"agent_memory_bytes"`
	DiskBytes                 uint64       `json:"disk_bytes"`
	AgentVersion              string       `json:"agent_version"`
	AgentBuild                string       `json:"agent_build"`
	SingBoxVersion            string       `json:"sing_box_version"`
	NetworkUploadBPS          uint64       `json:"network_upload_bps"`
	NetworkDownloadBPS        uint64       `json:"network_download_bps"`
	NetworkTotalUploadBytes   uint64       `json:"network_total_upload_bytes"`
	NetworkTotalDownloadBytes uint64       `json:"network_total_download_bytes"`
	ConnectivityProbeEnabled  bool         `json:"connectivity_probe_enabled"`
	ConnectivityProbeTarget   string       `json:"connectivity_probe_target"`
	ConnectivityAvailable     bool         `json:"connectivity_available"`
	ConnectivityLatencyMS     int64        `json:"connectivity_latency_ms"`
	ConnectivityCheckedAt     time.Time    `json:"connectivity_checked_at"`
	ConnectivityError         string       `json:"connectivity_error"`
	Timestamp                 time.Time    `json:"timestamp"`
}

type DashboardSummary struct {
	ServersTotal      int64 `json:"servers_total"`
	ServersOnline     int64 `json:"servers_online"`
	ServersOffline    int64 `json:"servers_offline"`
	ServersDegraded   int64 `json:"servers_degraded"`
	UsersTotal        int64 `json:"users_total"`
	UsersActive       int64 `json:"users_active"`
	TrafficUpload     int64 `json:"traffic_upload_bytes"`
	TrafficDownload   int64 `json:"traffic_download_bytes"`
	PendingTasks      int64 `json:"pending_tasks"`
	RunningTasks      int64 `json:"running_tasks"`
	FailedTasks       int64 `json:"failed_tasks"`
	LastConfigVersion int64 `json:"last_config_version"`
}

type VersionInfo struct {
	Name                 string   `json:"name"`
	Version              string   `json:"version"`
	Build                string   `json:"build"`
	Commit               string   `json:"commit"`
	BuiltAt              string   `json:"built_at"`
	Dev                  bool     `json:"dev"`
	AgentExpectedVersion string   `json:"agent_expected_version"`
	AgentExpectedBuild   string   `json:"agent_expected_build"`
	AgentUpdateRepo      string   `json:"agent_update_repo"`
	KernelVersion        string   `json:"kernel_version"`
	KernelBuild          string   `json:"kernel_build"`
	Protocols            []string `json:"protocols"`
	Kernel               string   `json:"kernel"`
	APIPrefix            string   `json:"api_prefix"`
}
