package license

import (
	"encoding/asn1"
	"errors"
)

var (
	// Errors related to Features
	ErrNoSuchFeature         = errors.New("license: No such feature")
	ErrFeatureAllreadyExists = errors.New("license: Feature already exists")
)

// Register Feature - register a feature into license registry so it will be recognized at Load time
func (l *License) RegisterFeature(name string, oid asn1.ObjectIdentifier) error {
	if l.knownFeatures == nil {
		l.knownFeatures = make(map[string]string)
	}
	_, found := l.knownFeatures[oid.String()]
	if found {
		return ErrFeatureAllreadyExists
	}
	l.knownFeatures[oid.String()] = name

	return nil
}

// Get Geature return the feature name and limit
func (l *License) GetFeature(oid asn1.ObjectIdentifier) (string, int64, error) {
	for _, feature := range l.Features {
		if feature.Oid.Equal(oid) {
			return l.knownFeatures[oid.String()], feature.Limit, nil
		}
	}
	return "", 0, ErrNoSuchFeature
}
