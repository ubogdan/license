package license

import (
	"encoding/asn1"
	"errors"
)

// RegisterFeature - register a feature into license registry so it will be recognized at Load time
func (l *License) RegisterFeature(name string, oid asn1.ObjectIdentifier) error {
	if l.knownFeatures == nil {
		l.knownFeatures = make(map[string]string)
	}
	index := oid.String()
	known, found := l.knownFeatures[index]
	if found {
		return errors.New("Feature `" + name + "` already registered as `" + known + "` with ObjectIdentifier " + index)
	}
	l.knownFeatures[oid.String()] = name
	return nil
}

// GetFeature - return the feature name and limit
func (l *License) GetFeature(oid asn1.ObjectIdentifier) (string, int64, error) {
	for _, feature := range l.Features {
		if feature.Oid.Equal(oid) {
			return l.knownFeatures[oid.String()], feature.Limit, nil
		}
	}
	return "", 0, errors.New("invalid or missing feature")
}
