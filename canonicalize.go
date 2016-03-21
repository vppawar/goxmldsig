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

// NOTE(russell_h): It looks like etree's canonical XML support doesn't
// re-order attributes. This call is an opportunity to do that, and correct
// any other other shortcomings until I can get the fixes upstream.
// NOTE(phoebe): Looks like etree also doesn't remove attributes that are
// duplicate namespaces. They should be removed if a parent has a matching one
func canonicalHack(el *etree.Element, seenSoFar map[string]bool) *etree.Element {
	_seenSoFar := make(map[string]bool)
	for k,v := range seenSoFar {
		_seenSoFar[k] = v
	}

	ne := el.Copy()
	sort.Sort(attrsByKey(ne.Attr))
	if len(ne.Attr) != 0 {
		for _, attr := range ne.Attr {
			if attr.Space != "xmlns" {
				continue
			}
			key := attr.Space + ":" + attr.Key
			if _seenSoFar[key] {
				ne.RemoveAttr(attr.Space + ":" + attr.Key)
			} else {
				_seenSoFar[key] = true
			}
		}
	}


	for i, token := range ne.Child {
		childElement, ok := token.(*etree.Element)
		if ok {
			ne.Child[i] = canonicalHack(childElement, _seenSoFar)
		}
	}

	return ne
}
