package license

// Customer godoc.
type Customer struct {
	Name               string `asn1:"optional,tag:0" json:"name,omitempty"`
	Country            string `asn1:"optional,tag:1" json:"country,omitempty"`
	City               string `asn1:"optional,tag:2" json:"city,omitempty"`
	Organization       string `asn1:"optional,tag:3" json:"organization,omitempty"`
	OrganizationalUnit string `asn1:"optional,tag:4" json:"organizational_unit,omitempty"`
}
