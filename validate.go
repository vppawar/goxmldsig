package dsig

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/beevik/etree"
)

var uriRegexp = regexp.MustCompile("^#[a-zA-Z_][\\w.-]*$")

type ValidationContext struct {
	CertificateStore X509CertificateStore
	IdAttribute      string
}

func NewDefaultValidationContext(certificateStore X509CertificateStore) *ValidationContext {
	return &ValidationContext{
		CertificateStore: certificateStore,
		IdAttribute:      DefaultIdAttr,
	}
}

// TODO(russell_h): More flexible namespace support. This might barely work.
func inNamespace(el *etree.Element, ns string) bool {
	for _, attr := range el.Attr {
		if attr.Value == ns {
			if attr.Space == "" && attr.Key == "xmlns" {
				return el.Space == ""
			} else if attr.Space == "xmlns" {
				return el.Space == attr.Key
			}
		}
	}

	return false
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	} else {
		return "./" + space + ":" + tag
	}
}

// The RemoveElement method on etree.Element isn't recursive...
func recursivelyRemoveElement(tree, el *etree.Element) bool {
	for i, child := range tree.Child {
		if childElement, ok := child.(*etree.Element); ok {
			if childElement == el {
				tree.Child = append(tree.Child[0:i], tree.Child[i+1:]...)
				childElement.Parent = nil
				return true
			}

			if recursivelyRemoveElement(childElement, el) {
				return true
			}
		}
	}

	return false
}

// NOTE(russell_h): Ideally this wouldn't mutate the root passed to it, and would
// instead return a copy. Unfortunately copying the tree makes it difficult to
// correctly locate the signature. I'm opting, for now, to simply mutate the root
// parameter.
func (ctx *ValidationContext) transform(root, sig *etree.Element, transforms []*etree.Element) (*etree.Element, string, error) {
	if len(transforms) != 2 {
		return nil, "", errors.New("Expected Enveloped and C14N transforms")
	}

	var c14nAlgorithm string

	for _, transform := range transforms {
		algo := transform.SelectAttr(AlgorithmAttr)
		if algo == nil {
			return nil, "", errors.New("Missing Algorithm attribute")
		}

		switch algo.Value {
		case EnvelopedSignatureAltorithmId:
			if !recursivelyRemoveElement(root, sig) {
				return nil, "", errors.New("Error applying canonicalization transform: Signature not found")
			}
		case CanonicalXML10AlgorithmId, CanonicalXML11AlgorithmId:
			c14nAlgorithm = algo.Value
		default:
			return nil, "", errors.New("Unknown Transform Algorithm: " + algo.Value)
		}
	}

	if c14nAlgorithm == "" {
		return nil, "", errors.New("Expected canonicalization transform")
	}

	return root, c14nAlgorithm, nil
}

func (ctx *ValidationContext) digest(el *etree.Element, digestAlgorithmId, c14nAlgorithmId string) ([]byte, error) {
	doc := etree.CreateDocument(canonicalHack(el))
	println(c14nAlgorithmId)
	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	digestAlgorithm, ok := digestAlgorithmsByIdentifier[digestAlgorithmId]
	if !ok {
		return nil, errors.New("Unknown digest algorithm: " + digestAlgorithmId)
	}

	str, _ := doc.WriteToString()
	println(str)

	hash := digestAlgorithm.New()
	_, err := doc.WriteTo(hash)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *ValidationContext) Validate(el *etree.Element) (*etree.Element, error) {
	el = el.Copy()

	sig := el.FindElement("//" + SignatureTag)
	if sig == nil {
		return nil, errors.New("Missing Signature")
	}

	if !inNamespace(sig, Namespace) {
		return nil, errors.New("Signature element is in the wrong namespace")
	}

	signedInfo := sig.FindElement(childPath(sig.Space, SignedInfoTag))
	if signedInfo == nil {
		return nil, errors.New("Missing SignedInfo")
	}

	reference := signedInfo.FindElement(childPath(sig.Space, ReferenceTag))
	if reference == nil {
		return nil, errors.New("Missing Reference")
	}

	transforms := reference.FindElement(childPath(sig.Space, TransformsTag))
	if transforms == nil {
		return nil, errors.New("Missing Transforms")
	}

	uri := reference.SelectAttr("URI")
	if uri == nil {
		// TODO(russell_h): It is permissible to leave this out. We should be
		// able to fall back to finding the referenced element some other way.
		return nil, errors.New("Reference is missing URI attribute")
	}

	if !uriRegexp.MatchString(uri.Value) {
		return nil, errors.New("Invalid URI: " + uri.Value)
	}

	referencedElement := el.FindElement(fmt.Sprintf("//[@%s='%s']", ctx.IdAttribute, uri.Value[1:]))
	if referencedElement == nil {
		return nil, errors.New("Unable to find referenced element: " + uri.Value)
	}

	transformed, c14nAlgorithmId, err := ctx.transform(referencedElement, sig, transforms.ChildElements())
	if err != nil {
		return nil, err
	}

	digestMethod := reference.FindElement(childPath(sig.Space, DigestMethodTag))
	if digestMethod == nil {
		return nil, errors.New("Missing DigestMethod")
	}

	digestAlgorithmAttr := digestMethod.SelectAttr(AlgorithmAttr)
	if digestAlgorithmAttr == nil {
		return nil, errors.New("Missing DigestMethod Algorithm attribute")
	}

	digest, err := ctx.digest(transformed, digestAlgorithmAttr.Value, c14nAlgorithmId)
	if err != nil {
		return nil, err
	}

	println(base64.StdEncoding.EncodeToString(digest))

	doc := etree.CreateDocument(transformed)

	doc.Indent(4)
	buf := &bytes.Buffer{}
	doc.WriteTo(buf)
	println(buf)
	return nil, nil
}
