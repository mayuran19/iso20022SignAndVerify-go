// This package implements the algorithm described in the
// xml-c14n (http://www.w3.org/TR/xml-c14n) documentation. It is largely a port
// of my javascript module (https://github.com/deoxxa/xml-c14n) which does the
// same thing.
package c14n

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"unicode/utf8"
)

var (
	ERR_UNKNOWN_PREFIX    = errors.New("unknown namespace prefix")
	ERR_UNKNOWN_TOKEN     = errors.New("unrecognised token type")
	ERR_INVALID_STRUCTURE = errors.New("invalid document structure")
	err_eob               = errors.New("end of branch")
)

// Canonicalise is the only exported method of this package. It takes an
// `xml.Decoder` and reads tokens from it, writing the canonlicalised XML stream
// to an `io.Writer`.
//
// If canonicalisation is successful, the return value will be nil. If there are
// any problems during canonicalisation, the return value will be an error
// object. If the error originates within this package, it will be one of the
// errors above. If the error originates outside this package, it will be passed
// through as-is.
//
// The `withComments` parameter controls whether or not the output XML has the
// comments stripped or not. If it is false, they will be stripped. If it is
// true, they will be retained.
//
// Right now there is no support for the "inclusive namespaces" feature from the
// specification.
func Canonicalise(xmlIn *xml.Decoder, xmlOut io.WriteCloser, withComments bool) error {
	seenDocument := false

	for {
		if wasDocument, err := processInner(xmlIn, xmlOut, seenDocument, false, prefixList{}, prefixList{}, "", withComments); err == io.EOF {
			break
		} else if err != nil {
			return err
		} else if wasDocument {
			seenDocument = wasDocument
		}
	}

	return nil
}

func escapeEntities(w io.Writer, data []byte, rep map[rune][]byte) error {
	last := 0
	for i := 0; i < len(data); {
		r, width := utf8.DecodeRune(data[i:])
		i += width

		if esc, ok := rep[r]; ok {
			if _, err := w.Write(data[last : i-width]); err != nil {
				return err
			}
			if _, err := w.Write(esc); err != nil {
				return err
			}

			last = i
		}
	}

	if _, err := w.Write(data[last:]); err != nil {
		return err
	}

	return nil
}

func escapeAttributeEntities(w io.Writer, data []byte) error {
	return escapeEntities(w, data, map[rune][]byte{
		'&':  []byte("&amp;"),
		'"':  []byte("&quot;"),
		'<':  []byte("&lt;"),
		'>':  []byte("&gt;"),
		'\t': []byte("&#x9;"),
		'\n': []byte("&#xA;"),
		'\r': []byte("&#xD;"),
	})
}

func escapeTextEntities(w io.Writer, data []byte) error {
	return escapeEntities(w, data, map[rune][]byte{
		'&':  []byte("&amp;"),
		'"':  []byte("&quot;"),
		'<':  []byte("&lt;"),
		'>':  []byte("&gt;"),
		'\r': []byte("&#xD;"),
	})
}

type prefix struct {
	prefix, namespace string
}

type prefixList []*prefix

func (l prefixList) clone() prefixList {
	return append(prefixList{}, l...)
}

func (l prefixList) get(name string) *prefix {
	for _, p := range l {
		if p.prefix == name {
			return p
		}
	}

	return nil
}

func (l prefixList) remove(name string) prefixList {
	for i, p := range l {
		if p.prefix == name {
			return append(l[:i], l[i+1:]...)
		}
	}

	return l
}

func (l prefixList) Len() int      { return len(l) }
func (l prefixList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l prefixList) Less(i, j int) bool {
	return l[i].prefix+":"+l[i].namespace < l[j].prefix+":"+l[j].namespace
}

type attributeList []xml.Attr

func (l attributeList) Len() int      { return len(l) }
func (l attributeList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l attributeList) Less(i, j int) bool {
	if l[i].Name.Space == "" && l[j].Name.Space != "" {
		return true
	} else if l[i].Name.Space != "" && l[j].Name.Space == "" {
		return false
	} else {
		return l[i].Name.Space+":"+l[i].Name.Local < l[j].Name.Space+":"+l[j].Name.Local
	}
}

func processInner(xmlIn *xml.Decoder, xmlOut io.WriteCloser, seenDocument bool, insideDocument bool, knownPrefixes prefixList, renderedPrefixes prefixList, defaultNamespace string, withComments bool) (bool, error) {
	token, err := xmlIn.RawToken()
	if err != nil {
		return false, err
	}

	if _, ok := token.(xml.Directive); ok {
		return false, nil
	}

	if charData, ok := token.(xml.CharData); ok {
		if !insideDocument {
			charData = bytes.Trim(charData, " \r\n")
		}

		if err := escapeTextEntities(xmlOut, charData); err != nil {
			return false, err
		}

		return false, nil
	}

	if comment, ok := token.(xml.Comment); ok {
		if !withComments {
			return false, nil
		}

		commentPrefix := ""
		commentSuffix := ""

		if !insideDocument && !seenDocument {
			commentSuffix = "\n"
		}

		if !insideDocument && seenDocument {
			commentPrefix = "\n"
		}

		if _, err := xmlOut.Write([]byte(commentPrefix + "<!--")); err != nil {
			return false, err
		}

		if err := escapeTextEntities(xmlOut, comment); err != nil {
			return false, err
		}

		if _, err := xmlOut.Write([]byte("-->" + commentSuffix)); err != nil {
			return false, err
		}

		return false, nil
	}

	if procInst, ok := token.(xml.ProcInst); ok {
		procInstPrefix := ""
		procInstSuffix := ""

		if !insideDocument && !seenDocument {
			procInstSuffix = "\n"
		}

		if !insideDocument && seenDocument {
			procInstPrefix = "\n"
		}

		space := ""
		if len(procInst.Inst) > 0 {
			space = " "
		}

		bits := [][]byte{
			[]byte(procInstPrefix + "<?" + procInst.Target + space),
			procInst.Inst,
			[]byte("?>" + procInstSuffix),
		}

		if _, err := xmlOut.Write(bytes.Join(bits, []byte{})); err != nil {
			return false, err
		}

		return false, nil
	}

	if _, ok := token.(xml.EndElement); ok {
		return false, err_eob
	}

	if startElement, ok := token.(xml.StartElement); ok {
		if seenDocument && !insideDocument {
			return false, ERR_INVALID_STRUCTURE
		}

		if _, err := xmlOut.Write([]byte("<")); err != nil {
			return true, err
		}

		space := ""
		if startElement.Name.Space != "" {
			space = startElement.Name.Space + ":"
		}

		if _, err := xmlOut.Write([]byte(space + startElement.Name.Local)); err != nil {
			return true, err
		}

		newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err := renderNamespace(xmlOut, startElement, knownPrefixes, renderedPrefixes, defaultNamespace)
		if err != nil {
			return true, err
		}

		if err := renderAttributes(xmlOut, startElement); err != nil {
			return true, err
		}

		if _, err := xmlOut.Write([]byte(">")); err != nil {
			return true, err
		}

		for {
			if _, err := processInner(xmlIn, xmlOut, seenDocument, true, newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, withComments); err == err_eob {
				break
			} else if err != nil {
				return true, err
			}
		}

		if _, err := xmlOut.Write([]byte("</" + space + startElement.Name.Local + ">")); err != nil {
			return true, err
		}

		return true, nil
	}

	return false, ERR_UNKNOWN_TOKEN
}

func renderAttributes(xmlOut io.Writer, t xml.StartElement) error {
	sort.Sort(attributeList(t.Attr))

	for _, v := range t.Attr {
		if v.Name.Space == "xmlns" || (v.Name.Space == "" && v.Name.Local == "xmlns") {
			continue
		}

		name := v.Name.Local
		if v.Name.Space != "" {
			name = v.Name.Space + ":" + name
		}

		if _, err := xmlOut.Write([]byte(" " + name + "=\"")); err != nil {
			return err
		}

		if err := escapeAttributeEntities(xmlOut, []byte(v.Value)); err != nil {
			return err
		}

		if _, err := xmlOut.Write([]byte("\"")); err != nil {
			return err
		}
	}

	return nil
}

func renderNamespace(xmlOut io.Writer, t xml.StartElement, knownPrefixes prefixList, renderedPrefixes prefixList, defaultNamespace string) (prefixList, prefixList, string, error) {
	newKnownPrefixes := knownPrefixes.clone()
	newRenderedPrefixes := renderedPrefixes.clone()
	newDefaultNamespace := defaultNamespace
	nsListToRender := prefixList{}

	for _, v := range t.Attr {
		if v.Name.Space == "" && v.Name.Local == "xmlns" {
			newDefaultNamespace = v.Value
		} else if v.Name.Space == "xmlns" {
			knownPrefix := newKnownPrefixes.get(v.Name.Local)

			if knownPrefix != nil && knownPrefix.namespace != v.Value {
				newKnownPrefixes = newKnownPrefixes.remove(knownPrefix.prefix)
				knownPrefix = nil
			}

			if knownPrefix == nil {
				knownPrefix := &prefix{
					prefix:    v.Name.Local,
					namespace: v.Value,
				}

				newKnownPrefixes = append(newKnownPrefixes, knownPrefix)
			}
		}
	}

	for _, v := range t.Attr {
		if v.Name.Space == "xmlns" || v.Name.Space == "" {
			continue
		}

		renderedPrefix := newRenderedPrefixes.get(v.Name.Space)
		knownPrefix := newKnownPrefixes.get(v.Name.Space)

		if knownPrefix == nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, ERR_UNKNOWN_PREFIX
		}

		if renderedPrefix != nil && renderedPrefix.namespace != knownPrefix.namespace {
			newRenderedPrefixes = newRenderedPrefixes.remove(renderedPrefix.prefix)
			renderedPrefix = nil
		}

		if renderedPrefix == nil {
			newRenderedPrefixes = append(newRenderedPrefixes, knownPrefix)
			nsListToRender = append(nsListToRender, knownPrefix)
		}
	}

	if t.Name.Space != "" {
		renderedPrefix := newRenderedPrefixes.get(t.Name.Space)
		knownPrefix := newKnownPrefixes.get(t.Name.Space)

		if knownPrefix == nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, ERR_UNKNOWN_PREFIX
		}

		if renderedPrefix != nil && renderedPrefix.namespace != knownPrefix.namespace {
			newRenderedPrefixes = newRenderedPrefixes.remove(renderedPrefix.prefix)
			renderedPrefix = nil
		}

		if renderedPrefix == nil {
			newRenderedPrefixes = append(newRenderedPrefixes, knownPrefix)
			nsListToRender = append(nsListToRender, knownPrefix)
		}
	} else if newDefaultNamespace != defaultNamespace {
		if _, err := xmlOut.Write([]byte(" xmlns=\"")); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}

		if err := escapeAttributeEntities(xmlOut, []byte(newDefaultNamespace)); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}

		if _, err := xmlOut.Write([]byte("\"")); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}
	}

	sort.Sort(nsListToRender)

	for _, v := range nsListToRender {
		if _, err := xmlOut.Write([]byte(" xmlns:" + v.prefix + "=\"")); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}

		if err := escapeAttributeEntities(xmlOut, []byte(v.namespace)); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}

		if _, err := xmlOut.Write([]byte("\"")); err != nil {
			return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, err
		}
	}

	return newKnownPrefixes, newRenderedPrefixes, newDefaultNamespace, nil
}
