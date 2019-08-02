package license

import (
	"time"
)

type Validity struct {
	From  time.Time `json:"from,omitempty" asn1:"default:0"`
	Until time.Time `json:"until,omitempty" asn1:"default:0"`
}

func (v Validity) IsValid(now time.Time) bool {
	if now.Before(v.From) {
		return false
	}
	if now.After(v.Until) {
		return false
	}
	return true
}
