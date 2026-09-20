package auditwire

const MaxReportBytes = 1 << 20
const MaxPendingBytes = 16 << 20
const MaxPending = 256

type Item struct {
	UserID        int64  `json:"user_id"`
	InboundID     int64  `json:"inbound_id"`
	PathID        int64  `json:"path_id"`
	SourcePrefix  string `json:"source_prefix"`
	ActivityBits  uint16 `json:"activity_bits"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
}
type Report struct {
	CollectorBootID      string `json:"collector_boot_id"`
	CollectorStartedAt   int64  `json:"collector_started_at"`
	StreamType           string `json:"stream_type"`
	Sequence             uint64 `json:"sequence"`
	MinuteUnix           int64  `json:"minute_unix"`
	ClockState           string `json:"clock_state"`
	Complete             bool   `json:"complete"`
	DroppedUpdates       uint64 `json:"dropped_updates"`
	UnknownSourceUpdates uint64 `json:"unknown_source_updates"`
	Items                []Item `json:"items"`
}
type Ack struct {
	CollectorBootID string `json:"collector_boot_id,omitempty"`
	Sequence        uint64 `json:"sequence"`
	Accepted        bool   `json:"accepted"`
	Duplicate       bool   `json:"duplicate"`
	Terminal        bool   `json:"terminal"`
	Reason          string `json:"reason,omitempty"`
}
