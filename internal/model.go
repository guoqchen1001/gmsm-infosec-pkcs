package internal

import (
	"encoding/asn1"
	"math/big"
)

var (
	OidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OidSignedDataSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	OidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OidSM3           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	OidSM3withSM2    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	OidSM2Encrypt    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}
	OidSM4           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
)

type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"tag:0,optional,set"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}
type SignerInfo struct {
	Version                   int
	IssuerAndSerialNumber     IssuerAndSerialNumber
	DigestAlgorithm           AlgorithmIdentifier
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
}
type EnvelopedData struct {
	Version              int
	RecipientInfos       []RecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}
type RecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  IssuerAndSerialNumber
	KeyEncryptionAlgorithm AlgorithmIdentifier
	EncryptedKey           []byte
}
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,implicit"`
}
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"tag:0,explicit,optional"`
}
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type sm2CipherASN1 struct {
	X, Y *big.Int
	C3   []byte
	C2   []byte
}
