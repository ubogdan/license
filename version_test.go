package license

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVersion_String(t *testing.T) {

	tests := []struct {
		version Version
		expect  string
	}{
		{
			version: Version(301001234),
			expect:  "3.100.1234",
		},
		{
			version: Version(1001234),
			expect:  "0.100.1234",
		},
		{
			version: Version(10001),
			expect:  "0.1.1",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.version.String(), test.expect)
	}
}
func TestNewVersion(t *testing.T) {
	tests := []struct {
		version    string
		expect     Version
		shouldFail bool
	}{
		{
			version: "0.1.1",
			expect:  Version(10001),
		},
		{
			version: "3.100.1234",
			expect:  Version(301001234),
		},
		{
			version: "1.1",
			expect:  Version(100010000),
		},
		{
			version: "1.1.1",
			expect:  Version(100010001),
		},
		{
			version:    "1.1.faulty",
			shouldFail: true,
		},
	}
	for _, test := range tests {
		val, err := NewVersion(test.version)
		if test.shouldFail {
			assert.Error(t, err)
		} else {
			assert.Equal(t, val, test.expect)
		}

	}
}
