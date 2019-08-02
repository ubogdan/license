package license

type Customer struct {
	Name               string
	Country            string `asn1:"optional,omitempty"`
	City               string `asn1:"optional,omitempty"`
	Organization       string `asn1:"optional,omitempty"`
	OrganizationalUnit string `asn1:"optional,omitempty"`
}
