package auditwire

import "time"

type CollectionPolicy struct {
	Mode              string    `json:"mode"`
	BaseMode          string    `json:"base_mode,omitempty"`
	DiagnosticUserIDs []int64   `json:"diagnostic_user_ids"`
	DiagnosticUntil   time.Time `json:"diagnostic_until"`
	Revision          int64     `json:"revision"`
}

func (p CollectionPolicy) Valid() bool {
	if p.Revision < 0 || len(p.DiagnosticUserIDs) > 256 || (p.BaseMode != "" && p.BaseMode != "light" && p.BaseMode != "standard") {
		return false
	}
	switch p.Mode {
	case "light", "standard":
		return len(p.DiagnosticUserIDs) == 0
	case "diagnostic":
		if p.DiagnosticUntil.IsZero() {
			return false
		}
		for _, id := range p.DiagnosticUserIDs {
			if id <= 0 {
				return false
			}
		}
		return true
	}
	return false
}
func (p *CollectionPolicy) Allows(user int64, now time.Time) bool {
	if p == nil {
		return false
	}
	if p.Mode == "standard" {
		return true
	}
	if p.Mode != "diagnostic" {
		return false
	}
	if !now.Before(p.DiagnosticUntil) {
		return p.BaseMode == "standard"
	}
	if len(p.DiagnosticUserIDs) == 0 {
		return true
	}
	for _, id := range p.DiagnosticUserIDs {
		if id == user {
			return true
		}
	}
	return false
}
