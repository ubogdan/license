package license

import (
	"encoding/asn1"
)

// Feature godoc.
type Feature struct {
	Oid         asn1.ObjectIdentifier `json:"-"`
	Description string                `asn1:"-" json:"description"`
	Expire      int64                 `asn1:"optional,tag:1"`
	Limit       int64                 `asn1:"optional,tag:2"`
}
