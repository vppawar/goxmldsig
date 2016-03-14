package dsig

import (
	"sort"

	"github.com/beevik/etree"
)

type attrsByKey []etree.Attr

func composeAttr(space, key string) string {
	if space != "" {
		return space + ":" + key
	} else {
		return key
	}
}

func (a attrsByKey) Len() int {
	return len(a)
}

func (a attrsByKey) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a attrsByKey) Less(i, j int) bool {
	// As I understand it: any "xmlns" attribute should come first, followed by any
	// any "xmlns:prefix" attributes, presumably ordered by prefix. Lastly any other
	// attributes in lexicographical order.
	if a[i].Space == "" && a[i].Key == "xmlns" {
		return true
	}

	if a[i].Space == "xmlns" {
		if a[j].Space == "xmlns" {
			return a[i].Key < a[j].Key
		} else {
			return true
		}
	}

	if a[j].Space == "xmlns" {
		return false
	}

	return composeAttr(a[i].Space, a[i].Key) < composeAttr(a[j].Space, a[j].Key)
}

// NOTE(russell_h): It looks like etree's canoninical XML support doesn't
// re-order attributes. This call is an opportunity to do that, and correct
// any other other shortcomings until I can get the fixes upstream.
func canonicalHack(el *etree.Element) *etree.Element {
	ne := el.Copy()
	sort.Sort(attrsByKey(ne.Attr))

	for i, token := range el.Child {
		childElement, ok := token.(*etree.Element)
		if ok {
			el.Child[i] = canonicalHack(childElement)
		}
	}

	return ne
}
