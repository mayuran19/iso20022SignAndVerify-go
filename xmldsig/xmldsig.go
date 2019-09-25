package xmldsig

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fknsrs.biz/p/xml/c14n"
	"fmt"
	"github.com/beevik/etree"
	"github.com/lestrrat-go/libxml2/parser"
	"github.com/lestrrat-go/libxml2/types"
	"io"
	"io/ioutil"
	"strings"
)

/*
The C14N library expect a WriteCloser type
 */
type XmlWriteCloser struct {
	io.Writer
}

/*
Implement the Close() method of the WriteCloser Interface
 */
func (XmlWriteCloser) Close() error {
	return nil
}

func newSignature() *Signature {
	signature := &Signature{}
	signature.SignedInfo.CanonicalizationMethod.Algorithm =
		"http://www.w3.org/2001/10/xml-exc-c14n#"
	transforms := &signature.SignedInfo.Reference.Transforms.Transform
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
	return signature
}

func CreateSignature(xmlString string) (string, error) {
	signature := newSignature()
	signature.SignedInfo.SignatureMethod.Algorithm = "http://www.w3.org/2009/xmldsig11#rsa-sha256"
	signature.SignedInfo.Reference.DigestMethod.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	// canonicalize the Item

	c14nPayload := Canonicalise(xmlString)
	fmt.Println("Canonicalise to be signed start")
	fmt.Println(c14nPayload)
	c14nPayloadDigest := GetSHA256Hash(c14nPayload)
	fmt.Println("Canonicalise to be signed end")

	signature.SignedInfo.Reference.DigestValue = base64.StdEncoding.EncodeToString(c14nPayloadDigest)

	// canonicalize the SignedInfo
	sinnatureInfoXML, _ := EncodeToXMLString(signature.SignedInfo)
	sinnatureInfoXMLC14N := Canonicalise(sinnatureInfoXML)
	//fmt.Println("Signinfo: %s", sinnatureInfoXML)
	//fmt.Println("Signinfo: %s", sinnatureInfoXMLC14N)

	sig, _ := Sign(sinnatureInfoXMLC14N)
	fmt.Println("xml to be singed start")
	fmt.Println(sinnatureInfoXMLC14N)
	fmt.Println("xml to be singed end")
	//sig, err := s.Sign(canonData)
	signature.SignatureValue = base64.StdEncoding.EncodeToString(sig)
	x509Data := &X509Data{X509Certificate: "public key"}
	signature.KeyInfo.X509Data = x509Data
	s, _ := EncodeToXMLString(signature)
	//fmt.Println("Signature: %s", s)

	return s, nil
}

func SignXML(xml string) string {
	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(xml)
	HandleError(err)
	n, err := doc.DocumentElement()
	nodeList, err := n.ChildNodes()

	signature,err := CreateSignature(xml)
	d, err := p.ParseString(signature)
	dd, err := d.DocumentElement()
	HandleError(err)
	fmt.Println("Text content: %s", dd.TextContent())
	for _, node := range nodeList {
		if(node.NodeName() == "AppHdr"){
			node.AddChild(dd)
			break
		}
	}

	return doc.String()
}

func SignXML2(xml string) string {
	doc := etree.NewDocument()
	doc.ReadFromString(xml)

	signature, err := CreateSignature(xml)

	HandleError(err)
	doc2 := etree.NewDocument()
	doc2.ReadFromString(signature)

	for _, element := range doc.Root().ChildElements(){
		fmt.Println(element.Tag)
		if(element.Tag == "AppHdr"){
			element.AddChild(doc2.Root())
		}
	}
	s, err := doc.WriteToString()
	return s
}

func VerifySignature2(xml string)  {
	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(xml)
	HandleError(err)
	rootNode, err := doc.DocumentElement()
	appHeaderNode := GetNodeByTagName(rootNode, "AppHdr")
	signatureNode := GetNodeByTagName(appHeaderNode, "Signature")
	signInfoNode := GetNodeByTagName(signatureNode, "SignedInfo")
	keyInfoNode := GetNodeByTagName(signatureNode, "KeyInfo")
	x509DataNode := GetNodeByTagName(keyInfoNode, "X509Data")
	x509CertificateNode := GetNodeByTagName(x509DataNode, "X509Certificate")
	signatureValueNode := GetNodeByTagName(signatureNode, "SignatureValue")
	referenceNode := GetNodeByTagName(signInfoNode, "Reference")
	digentValueNode := GetNodeByTagName(referenceNode, "DigestValue")

	err = appHeaderNode.RemoveChild(signatureNode)
	fmt.Println("err: %s", err)
	c14nPayload := Canonicalise(doc.String())
	fmt.Println("Content to be verified start")
	fmt.Println(c14nPayload)
	fmt.Println("Content to be verified end")

	c14nPayloadDigest := GetSHA256Hash(c14nPayload)
	digestBase64 := base64.StdEncoding.EncodeToString(c14nPayloadDigest)
	fmt.Println("digestBase64: %s", digestBase64)

	publicKay := x509CertificateNode.TextContent()
	digest := digentValueNode.TextContent()
	signature := signatureValueNode.TextContent()

	fmt.Println("publicKey: %s", publicKay)
	fmt.Println("digest: %s", digest)
	fmt.Println("signature: %s", signature)
}

func GetNodeByTagName(nodeElement types.Node, tagName string) types.Node {
	nodes, _ := nodeElement.ChildNodes()
	for _, element := range nodes{
		if(element.NodeName() == tagName){
			return element
		}
	}

	return nil
}

func VerifySignature(xml string) bool {
	doc := etree.NewDocument()
	doc.ReadFromString(xml)
	appHeaderElement := GetElementByName(doc.Root(), "AppHdr")
	signatureElement := GetElementByName(appHeaderElement, "Signature")
	signInfoElement := GetElementByName(signatureElement, "SignedInfo")
	keyInfoElement := GetElementByName(signatureElement, "KeyInfo")
	x509DataElement := GetElementByName(keyInfoElement, "X509Data")
	x509Certificate := GetElementByName(x509DataElement, "X509Certificate")
	signatureValueElement := GetElementByName(signatureElement, "SignatureValue")
	referenceElement := GetElementByName(signInfoElement, "Reference")
	digentValueElement := GetElementByName(referenceElement, "DigestValue")


	doc2 := etree.NewDocument()
	doc2.AddChild(signInfoElement)
	s1, _ := doc2.WriteToString()
	signinfoCan := Canonicalise(s1)
	fmt.Println("xml to be verified start")
	fmt.Println(signinfoCan)
	fmt.Println("xml to be verified start")

	publicKay := x509Certificate.Text()
	digest := digentValueElement.Text()
	signature := signatureValueElement.Text()

	appHeaderElement.RemoveChild(signatureElement)

	fmt.Println("publicKey: %s", publicKay)
	fmt.Println("digest: %s", digest)
	fmt.Println("signature: %s", signature)

	s, _ := doc.WriteToString()
	fmt.Println("XML after removing signinfo start")
	fmt.Println(s)
	fmt.Println("XML after removing signinfo end")

	c14nPayload := Canonicalise(s)
	fmt.Println("Content to be verified start")
	fmt.Println(c14nPayload)
	fmt.Println("Content to be verified end")

	c14nPayloadDigest := GetSHA256Hash(c14nPayload)
	digestBase64 := base64.StdEncoding.EncodeToString(c14nPayloadDigest)
	fmt.Println("digestBase64: %s", digestBase64)

	a, _ := ioutil.ReadFile("certificate.pem")
	block, _ := pem.Decode(a)
	certificate, err := x509.ParseCertificate(block.Bytes)
	rsaPublicKey := certificate.PublicKey.(*rsa.PublicKey)

	signatureByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Signature decoding error",err)
		return false
	}

	hash := GetSHA256Hash(signinfoCan)
	fmt.Println("checksum to verify:", base64.StdEncoding.EncodeToString(hash))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signatureByte)
	if err != nil {
		fmt.Println(err)
	}else{
		fmt.Println("Validated successfully")
	}

	return true
}

func GetElementByName(element *etree.Element, tag string) *etree.Element  {
	for _, child := range element.ChildElements(){
		if(child.Tag == tag){
			return child
		}
	}

	return nil
}

func Canonicalise(xmlString string) string {
	decoder := xml.NewDecoder(strings.NewReader(xmlString))
	buf := bytes.NewBufferString("")
	xmlWriter := XmlWriteCloser{buf}
	c14n.Canonicalise(decoder, xmlWriter, true)

	return buf.String()
}

func GetSHA256Hash(val string) []byte {
	hash := sha256.New()
	hash.Write([]byte(val))
	checksum := hash.Sum(nil)
	//digest := base64.StdEncoding.EncodeToString(checksum)
	return checksum
}

func EncodeToXMLString(data interface{}) (string, error) {
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	encoder := xml.NewEncoder(writer)
	err := encoder.Encode(data)
	if err != nil {
		return "", err
	}
	encoder.Flush()
	return buffer.String(),nil
}

func UnmarshallSignatureTag(val string) Signature {
	signature := Signature{}
	err := xml.Unmarshal([]byte(val), &signature)
	HandleError(err)

	return signature
}

/*
Messaged will be hashed and signed
 */
func Sign(data string) ([]byte, error) {
	cert, err := tls.LoadX509KeyPair("certificate.pem", "key.pem")
	HandleError(err)
	signer := cert.PrivateKey.(crypto.Signer)
	checkSumToSign := GetSHA256Hash(data)
	fmt.Println("checksum to sign:", base64.StdEncoding.EncodeToString(checkSumToSign))
	signature, err := signer.Sign(rand.Reader, checkSumToSign, crypto.SHA256)
	HandleError(err)
	return signature, nil
}

/*func Verify(digest string, signature string) bool {
	content, err := ioutil.ReadFile("certificate.pem")
	HandleError(err)
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return false
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	pubKey := key.(*rsa.PublicKey)

	signatureByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
}*/

func HandleError(err error)  {
	if(err != nil){
		fmt.Println("Error: %v", err)
		return
	}
}

// Signature element is the root element of an XML Signature.
type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo
	SignatureValue string `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfo        KeyInfo
}

// Algorithm describes the digest or signature used when digest or signature.
type Algorithm struct {
	Algorithm string `xml:",attr"`
}

// SignedInfo includes a canonicalization algorithm, a signature algorithm, and a reference.
type SignedInfo struct {
	XMLName                xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              Reference
}

// Reference specifies a digest algorithm and digest value, and optionally an identifier of the object being signed, the type of the object, and/or a list of transforms to be applied prior to digesting.
type Reference struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string   `xml:",attr,omitempty"`
	Transforms   Transforms
	DigestMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string    `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// Transforms is an optional ordered list of processing steps that were applied to the resource's content before it was digested.
type Transforms struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transform []Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

// KeyInfo is an optional element that enables the recipient(s) to obtain the key needed to validate the signature.
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data *X509Data
	Children []interface{}
}

// X509Data element within KeyInfo contains one an X509 certificate
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}