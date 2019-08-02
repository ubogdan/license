package license

import (
	"encoding/asn1"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAddFeature(t *testing.T) {

	tests := []struct {
		Feature    Feature
		ShouldFail bool
	}{
		{
			Feature: Feature{
				Oid: asn1.ObjectIdentifier{1, 3, 1, 1},
			},
			ShouldFail: false,
		},
		{
			Feature: Feature{
				Oid: asn1.ObjectIdentifier{1, 3, 2, 1},
			},
			ShouldFail: false,
		},
		{
			Feature: Feature{
				Oid: asn1.ObjectIdentifier{1, 3, 1, 1, 1},
			},
			ShouldFail: false,
		},
		{
			Feature: Feature{
				Oid: asn1.ObjectIdentifier{1, 3, 1, 1},
			},
			ShouldFail: true,
		},
	}

	l := &License{}

	for _, test := range tests {
		err := l.RegisterFeature("", test.Feature.Oid)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
