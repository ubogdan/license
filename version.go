package license

import (
	"fmt"
	"strconv"
	"strings"
)

type Version int64

// String convert version integer to string
func (ver Version) String() string {
	tmp := ver
	v := make([]string, 3)
	for i := 2; i >= 0; i-- {
		rest := int64(tmp) % 10000
		v[i] = strconv.FormatInt(rest, 10)
		tmp = tmp / 10000
	}
	return strings.Join(v, ".")
}

// NewVersion semantic version to integer
// valid format XXXX.XXXX.XXXX
func NewVersion(v string) (Version, error) {
	sections := strings.Split(v, ".")
	intVerSection := func(v string, n int) string {
		if n < len(sections) {
			return fmt.Sprintf("%04s", sections[n])
		} else {
			return "0000"
		}
	}
	s := ""
	for i := 0; i < 3; i++ {
		s += intVerSection(v, i)
	}
	version, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return Version(version), nil
}
