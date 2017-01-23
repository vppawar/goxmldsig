package dsig

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

const (
	assertion       = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0" IssueInstant="2016-04-28T15:37:17" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO"><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	c14n11          = `<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	assertionC14ned = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
)

const (
	xmldoc                             = `<Foo ID="id1619705532971228558789260" xmlns:bar="urn:bar" xmlns="urn:foo"><bar:Baz></bar:Baz></Foo>`
	xmldocC14N10ExclusiveCanonicalized = `<Foo xmlns="urn:foo" ID="id1619705532971228558789260"><bar:Baz xmlns:bar="urn:bar"></bar:Baz></Foo>`
	xmldocC14N11Canonicalized          = `<Foo xmlns="urn:foo" xmlns:bar="urn:bar" ID="id1619705532971228558789260"><bar:Baz></bar:Baz></Foo>`
)

func runCanonicalizationTest(t *testing.T, useC14N10ExclusiveCanonicalizer bool, xmlstr string, canonicalXmlstr string) {
	var canonicalizer Canonicalizer
	if useC14N10ExclusiveCanonicalizer {
		canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	} else {
		canonicalizer = MakeC14N11Canonicalizer()
	}

	raw := etree.NewDocument()
	err := raw.ReadFromString(xmlstr)
	require.NoError(t, err)

	canonicalized, err := canonicalizer.Canonicalize(raw.Root())
	require.NoError(t, err)
	require.Equal(t, canonicalXmlstr, string(canonicalized))
}

func TestExcC14N10(t *testing.T) {
	runCanonicalizationTest(t, true, assertion, assertionC14ned)
}

func TestC14N11(t *testing.T) {
	runCanonicalizationTest(t, false, assertion, c14n11)
}

func TestXmldocC14N10Exclusive(t *testing.T) {
	runCanonicalizationTest(t, true, xmldoc, xmldocC14N10ExclusiveCanonicalized)
}

func TestXmldocC14N11(t *testing.T) {
	runCanonicalizationTest(t, false, xmldoc, xmldocC14N11Canonicalized)
}
