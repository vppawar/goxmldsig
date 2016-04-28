package dsig

import (
	"fmt"
	"sort"

	"github.com/beevik/etree"
)

type attrsByKey []etree.Attr

func composeAttr(space, key string) string {
	if space != "" {
		return space + ":" + key
	}

	return key
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
		}
		return true
	}

	if a[j].Space == "xmlns" {
		return false
	}

	return composeAttr(a[i].Space, a[i].Key) < composeAttr(a[j].Space, a[j].Key)
}

func _canonicalHack(el *etree.Element, seenSoFar map[string]struct{}) *etree.Element {
	_seenSoFar := make(map[string]struct{})
	for k, v := range seenSoFar {
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
			if _, seen := _seenSoFar[key]; seen {
				ne.RemoveAttr(attr.Space + ":" + attr.Key)
			} else {
				_seenSoFar[key] = struct{}{}
			}
		}
	}

	for i, token := range ne.Child {
		childElement, ok := token.(*etree.Element)
		if ok {
			ne.Child[i] = _canonicalHack(childElement, _seenSoFar)
		}
	}

	return ne
}

// NOTE(russell_h): It looks like etree's canonical XML support doesn't
// re-order attributes. This call is an opportunity to do that, and correct
// any other other shortcomings until I can get the fixes upstream.
// NOTE(phoebe): Looks like etree also doesn't remove attributes that are
// duplicate namespaces. They should be removed if a parent has a matching one
// NOTE(astuart): namespaces must also be moved to the first element at which they're used
func canonicalHack(el *etree.Element) *etree.Element {
	attrMap := make(map[string]struct{})
	return _canonicalHack(el, attrMap)
}

func getNsDecl(a etree.Attr) string {
	return fmt.Sprintf("xmlns:%s", a.Key)
}

type c14nSpace struct {
	a    etree.Attr
	used bool
}

const nsSpace = "xmlns"

func _excCanonicalPrep(el *etree.Element, _alreadyDeclared map[string]c14nSpace) *etree.Element {
	//Copy alreadyDeclared map
	alreadyDeclared := make(map[string]c14nSpace, len(_alreadyDeclared))
	for k := range _alreadyDeclared {
		alreadyDeclared[k] = _alreadyDeclared[k]
	}

	usedHere := make(map[string]struct{})

	if el.Space != "" {
		usedHere[el.Space] = struct{}{}
	}

	toRemove := make([]string, 0, 0)

	for _, a := range el.Attr {
		switch a.Space {
		case nsSpace:
			toRemove = append(toRemove, a.Space+":"+a.Key)
			if _, ok := alreadyDeclared[a.Key]; !ok {
				alreadyDeclared[a.Key] = c14nSpace{a: a, used: false}
			}
		default:
			if a.Space != "" {
				usedHere[a.Space] = struct{}{}
			}
		}
	}
	for _, attrK := range toRemove {
		el.RemoveAttr(attrK)
	}

	for k := range usedHere {
		spc := alreadyDeclared[k]
		//If previously unused, mark as used
		if !spc.used {
			el.Attr = append(el.Attr, spc.a)
			spc.used = true
			alreadyDeclared[k] = spc
		}
	}

	for _, child := range el.ChildElements() {
		_excCanonicalPrep(child, alreadyDeclared)
	}

	sort.Sort(attrsByKey(el.Attr))

	//Sort

	return el.Copy()
}

func excCanonicalPrep(el *etree.Element) *etree.Element {
	return _excCanonicalPrep(el, make(map[string]c14nSpace))
}
