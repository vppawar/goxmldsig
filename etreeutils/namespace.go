package etreeutils

import (
	"errors"

	"fmt"

	"github.com/beevik/etree"
)

const (
	defaultPrefix = ""
	xmlnsPrefix   = "xmlns"
	xmlPrefix     = "xml"

	XMLNamespace   = "http://www.w3.org/XML/1998/namespace"
	XMLNSNamespace = "http://www.w3.org/2000/xmlns/"
)

var (
	DefaultNSContext = NSContext{
		prefixes: map[string]string{
			defaultPrefix: XMLNamespace,
			xmlPrefix:     XMLNamespace,
			xmlnsPrefix:   XMLNSNamespace,
		},
	}

	ErrReservedNamespace       = errors.New("disallowed declaration of reserved namespace")
	ErrInvalidDefaultNamespace = errors.New("invalid default namespace declaration")
)

type ErrUndeclaredNSPrefix struct {
	Prefix string
}

func (e ErrUndeclaredNSPrefix) Error() string {
	return fmt.Sprintf("undeclared namespace prefix: '%s'", e.Prefix)
}

type NSContext struct {
	prefixes map[string]string
}

func (ctx NSContext) SubContext(el *etree.Element) (NSContext, error) {
	// The subcontext should inherit existing declared prefixes
	prefixes := make(map[string]string, len(ctx.prefixes)+4)
	for k, v := range ctx.prefixes {
		prefixes[k] = v
	}

	// Merge new namespace declarations on top of existing ones.
	for _, attr := range el.Attr {
		if attr.Space == xmlnsPrefix {
			// This attribute is a namespace declaration of the form "xmlns:<prefix>"

			// The 'xml' namespace may only be re-declared with the name 'http://www.w3.org/XML/1998/namespace'
			if attr.Key == xmlPrefix && attr.Value != XMLNamespace {
				return ctx, ErrReservedNamespace
			}

			// The 'xmlns' namespace may not be re-declared
			if attr.Key == xmlnsPrefix {
				return ctx, ErrReservedNamespace
			}

			prefixes[attr.Key] = attr.Value
		} else if attr.Space == defaultPrefix && attr.Key == xmlnsPrefix {
			// This attribute is a default namespace declaration

			// The xmlns namespace value may not be declared as the default namespace
			if attr.Value == XMLNSNamespace {
				return ctx, ErrInvalidDefaultNamespace
			}

			prefixes[defaultPrefix] = attr.Value
		}
	}

	return NSContext{prefixes: prefixes}, nil
}

// LookupPrefix attempts to find a declared namespace for the specified prefix. If the prefix
// is an empty string this will be the default namespace for this context. If the prefix is
// undeclared in this context an ErrUndeclaredNSPrefix will be returned.
func (ctx NSContext) LookupPrefix(prefix string) (string, error) {
	if namespace, ok := ctx.prefixes[prefix]; ok {
		return namespace, nil
	}

	return "", ErrUndeclaredNSPrefix{
		Prefix: prefix,
	}
}

// BuildParentContext recurses upward from an element in order to build an NSContext
// for its immediate parent. If the element has no parent DefaultNSContext
// is returned.
func BuildParentContext(el *etree.Element) (NSContext, error) {
	parent := el.Parent()

	if parent == nil {
		return DefaultNSContext, nil
	}

	ctx, err := BuildParentContext(parent)
	if err != nil {
		return ctx, err
	}

	return ctx.SubContext(parent)
}

// FindElement behaves the same as FindElementInContext, but it first calls BuildParentContext
// in order to build a surrounding context for the passed element.
func FindElement(root *etree.Element, namespace, tag string) (*etree.Element, error) {
	ctx, err := BuildParentContext(root)
	if err != nil {
		return nil, err
	}

	return FindElementInContext(ctx, root, namespace, tag)
}

// FindElementInContext conducts a depth-first search starting at (and inclusive of)
// a root element, for an element with the specified namespace and tag. The passed
// NSContext is used for namespace resolution. The search is aggressive about namespace
// lookups - any failed lookup will cause the search to fail. If the search encounters
// no errors and finds no matching elements it will return nil.
func FindElementInContext(ctx NSContext, el *etree.Element, namespace, tag string) (*etree.Element, error) {
	ctx, err := ctx.SubContext(el)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Context (%s:%s):\n", el.Space, el.Tag)
	for prefix, namespace := range ctx.prefixes {
		fmt.Printf("  %s -> %s\n", prefix, namespace)
	}

	currentNS, err := ctx.LookupPrefix(el.Space)
	if err != nil {
		return nil, err
	}

	// Base case, el is the sought after element.
	if currentNS == namespace && el.Tag == tag {
		return el, nil
	}

	// Recursively search child elements instead.
	for _, child := range el.ChildElements() {
		el, err := FindElementInContext(ctx, child, namespace, tag)
		if err != nil {
			return nil, err
		}

		if el != nil {
			return el, nil
		}
	}

	return nil, nil
}
