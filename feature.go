package license

import (
	"encoding/asn1"
)

// Feature godoc.
type Feature struct {
	Oid         asn1.ObjectIdentifier `json:"-"`
	Description string                `json:"description"`
	Expire      int64                 `json:"expire,omitempty"`
	Limit       int64                 `json:"limit"`
}
