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
	"errors"
	"fknsrs.biz/p/xml/c14n"
	"github.com/beevik/etree"
	"github.com/op/go-logging"
	"io"
	"io/ioutil"
	"strings"
)

var LOGGER = logging.MustGetLogger("xmldsig")

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
	signature.SignedInfo.CanonicalizationMethod.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
	transforms := &signature.SignedInfo.Reference.Transforms.Transform
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
	signature.SignedInfo.SignatureMethod.Algorithm = "http://www.w3.org/2009/xmldsig11#rsa-sha256"
	signature.SignedInfo.Reference.DigestMethod.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	return signature
}

func generateSignatureTag(xml, publicKey string) (string, error) {
	//Initialise the Signature object with properties, values are hard coded only support SHA-256
	signature := newSignature()

	//Canonicalise the original xml payload
	canonicalisedPayload, err := Canonicalise(xml)
	if err != nil {
		return "", err
	}

	//Get the digest of the Canonicalised payload
	canonicalisedPayloadHashed, err := generateSHA256Hash(canonicalisedPayload)
	if err != nil {
		return "", err
	}

	//Based64 encode the canonicalised hashed payload
	canonicalisedPayloadHashedEncoded := base64.StdEncoding.EncodeToString(canonicalisedPayloadHashed)
	//set the hash to the Signature struct
	signature.SignedInfo.Reference.DigestValue = canonicalisedPayloadHashedEncoded

	//Now generate the SignedInfo tag by marshalling the struct to XML string
	signedInfoString, err := marshallToXML(signature.SignedInfo)
	if err != nil {
		return "", err
	}

	//Canonicalise the SignedInfo
	signedInfoStringCanonicalised, err := Canonicalise(signedInfoString)

	signedInfoSignature, err := signSignedInfo(signedInfoStringCanonicalised)
	if err != nil {
		return "", err
	}

	//Populate the Sigature object with hashed signaure value
	signature.SignatureValue = base64.StdEncoding.EncodeToString(signedInfoSignature)

	//Populate the public key
	x509Data := &X509Data{
		X509Certificate: publicKey,
	}
	signature.KeyInfo.X509Data = x509Data

	//Generate the XML from Signature object
	s, err := marshallToXML(signature)
	if err != nil {
		return "", err
	}

	return s, nil
}

func SignXML(xml, publicKey string) (string, error) {
	// Read the XML string and convert it to DOM object in memory
	payloadDocument := etree.NewDocument()
	err := payloadDocument.ReadFromString(xml)
	if(err != nil){
		return "", errors.New("Error while parsing XML into DOM")
	}

	signature, err := generateSignatureTag(xml, publicKey)
	if(err != nil){
		return "", err
	}

	//Create new XML node Signature
	signatureDocument := etree.NewDocument()
	signatureDocument.ReadFromString(signature)

	//Add the signatureDocument under AppHdr tag
	for _, element := range payloadDocument.Root().ChildElements(){
		if(element.Tag == "AppHdr"){
			element.AddChild(signatureDocument.Root())
		}
	}

	//Return the Signed XML document as String
	s, err := payloadDocument.WriteToString()
	if(err != nil){
		return "", err
	}
	return s, nil
}

func VerifySignature(xml string) bool {
	//Get the document object model
	signedDocument := etree.NewDocument()
	signedDocument.ReadFromString(xml)

	//Get appheader node
	appHeaderElement := GetElementByName(signedDocument.Root(), "AppHdr")

	//Get Signature node
	signatureElement := GetElementByName(appHeaderElement, "Signature")

	//Get signinfo node
	signInfoElement := GetElementByName(signatureElement, "SignedInfo")

	//Get keyinfo node
	keyInfoElement := GetElementByName(signatureElement, "KeyInfo")

	//
	x509DataElement := GetElementByName(keyInfoElement, "X509Data")

	//
	x509Certificate := GetElementByName(x509DataElement, "X509Certificate")

	//
	signatureValueElement := GetElementByName(signatureElement, "SignatureValue")

	//
	referenceElement := GetElementByName(signInfoElement, "Reference")

	//
	digentValueElement := GetElementByName(referenceElement, "DigestValue")

	//Read the values
	publicKay := x509Certificate.Text()
	digest := digentValueElement.Text()
	signature := signatureValueElement.Text()

	//Conver the SignedInfo node to String to calculate the hash for verification
	signedInfoDocument := etree.NewDocument()
	signedInfoDocument.AddChild(signInfoElement)
	signedInfoString, err := signedInfoDocument.WriteToString()
	if(err != nil){
		LOGGER.Errorf("Error occured while converting the SignedInfo node to String")
		return false
	}

	//Canonicalise the signedinfo
	signedInfoCanonicalisedString, err := Canonicalise(signedInfoString)

	//Remove the Signature element from AppHdr
	appHeaderElement.RemoveChild(signatureElement)

	payloadStringWithoutSignature, err := signedDocument.WriteToString()
	if(err != nil){
		LOGGER.Errorf("Error occured while converting the payload with removed sigature node to String")
		return false
	}

	payloadWithoutSignatureCanonicalised, err := Canonicalise(payloadStringWithoutSignature)
	if(err != nil){
		LOGGER.Errorf("Error occured while canonicalising the payloadStringWithoutSignature")
		return false
	}

	payloadDigestWithoutSignature, err := generateSHA256Hash(payloadWithoutSignatureCanonicalised)
	if(err != nil){
		LOGGER.Errorf("Error occured while hashing the payloadStringWithoutSignature")
		return false
	}

	payloadDigestWithoutSignatureBase64 := base64.StdEncoding.EncodeToString(payloadDigestWithoutSignature)
	LOGGER.Infof("Calculated digest of payload XML: %s", payloadDigestWithoutSignatureBase64)

	if(digest != payloadDigestWithoutSignatureBase64){
		LOGGER.Warningf("Digest in document and digest calculated doesn't match")
		return false
	}

	return doVerifySignatureUsingPEM(signature, signedInfoCanonicalisedString, publicKay)
}

func doVerifySignatureUsingPEM(signatureInPayload, signedInfoCanonicalisedString, publicKey string) bool {
	a, _ := ioutil.ReadFile("certificate.pem")
	block, _ := pem.Decode(a)
	certificate, err := x509.ParseCertificate(block.Bytes)
	rsaPublicKey := certificate.PublicKey.(*rsa.PublicKey)

	signatureByte, err := base64.StdEncoding.DecodeString(signatureInPayload)
	if err != nil {
		return false
	}

	hash, err := generateSHA256Hash(signedInfoCanonicalisedString)
	if err != nil {
		return false
	}

	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signatureByte)
	if err != nil {
		LOGGER.Warningf("Signature verification failed. %s", err)
		return false
	}else{
		LOGGER.Infof("Signature verification success")
		return true
	}
}

func GetElementByName(element *etree.Element, tag string) *etree.Element  {
	for _, child := range element.ChildElements(){
		if(child.Tag == tag){
			return child
		}
	}

	return nil
}

/*
Canonicalise the XML based on W3C standard, using another library
 */
func Canonicalise(xmlString string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlString))
	buf := bytes.NewBufferString("")

	//The library expect a WriteCloser, so create a type to implement the Close method
	xmlWriter := XmlWriteCloser{buf}
	err := c14n.Canonicalise(decoder, xmlWriter, true)
	if(err != nil){
		LOGGER.Infof("Error occured while canonicalising the XML payload. %s", err)
		return "", err
	}

	return buf.String(), nil
}

func generateSHA256Hash(val string) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(val))
	if(err != nil){
		LOGGER.Infof("Error occured while calculating the digest. %s", err)
		return nil, err
	}
	checksum := hash.Sum(nil)
	return checksum, nil
}

func marshallToXML(data interface{}) (string, error) {
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	encoder := xml.NewEncoder(writer)
	err := encoder.Encode(data)
	if err != nil {
		LOGGER.Infof("Error occured while marshalling the SignedInfo tag to XML. %s", err)
		return "", err
	}
	err = encoder.Flush()
	if err != nil {
		LOGGER.Infof("Error occured while Flush. %s", err)
		return "", err
	}
	return buffer.String(), nil
}

/*
Messaged will be hashed and signed
 */
func signSignedInfo(data string) ([]byte, error) {
	//Signing has to sign the hash of the SignedInfo
	checkSumToSign, err := generateSHA256Hash(data)
	if(err != nil){
		return nil, err
	}

	return doSignUsingPEM(checkSumToSign)
}

func doSignUsingPEM(data []byte) ([]byte, error) {
	//This is using the Self signed pem files, has to use HSM here
	cert, _ := tls.LoadX509KeyPair("certificate.pem", "key.pem")
	signer := cert.PrivateKey.(crypto.Signer)
	signature, err := signer.Sign(rand.Reader, data, crypto.SHA256)
	if(err != nil){
		LOGGER.Errorf("Error occured while signing using PEM files. %s", err)
		return nil, err
	}

	return signature, nil
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