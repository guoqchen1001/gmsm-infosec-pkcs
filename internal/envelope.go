package internal

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"math/big"
)

// MakeMSEnvelope 封装了签名和加密的完整流程
func MakeMSEnvelope(clientPrivateKey *sm2.PrivateKey, bankCert *x509.Certificate, clientCert *x509.Certificate, plainText string) (string, error) {

	// 签名
	signedBytes, err := Signed(clientPrivateKey, clientCert, []byte(plainText))
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}

	// 加密/封装
	envelopedBytes, err := Enveloped(bankCert, signedBytes)
	if err != nil {
		return "", fmt.Errorf("加密封装失败: %w", err)
	}

	// Base64 编码
	envelopedStr := base64.StdEncoding.EncodeToString(envelopedBytes)

	return envelopedStr, nil
}

func Signed(priKey *sm2.PrivateKey, signCert *x509.Certificate, originData []byte) ([]byte, error) {
	var nullParam asn1.RawValue
	nullParam.Tag = asn1.TagNull
	signature, err := priKey.Sign(rand.Reader, originData, nil)
	if err != nil {
		return nil, err
	}
	signerInfo := SignerInfo{
		Version:                   1,
		IssuerAndSerialNumber:     IssuerAndSerialNumber{Issuer: asn1.RawValue{FullBytes: signCert.RawIssuer}, SerialNumber: signCert.SerialNumber},
		DigestAlgorithm:           AlgorithmIdentifier{Algorithm: OidSM3, Parameters: nullParam},
		DigestEncryptionAlgorithm: AlgorithmIdentifier{Algorithm: OidSM3withSM2, Parameters: nullParam},
		EncryptedDigest:           signature,
	}
	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{{Algorithm: OidSM3, Parameters: nullParam}},
		EncapContentInfo: EncapsulatedContentInfo{ContentType: OidData, Content: originData},
		Certificates:     []asn1.RawValue{{FullBytes: signCert.Raw}},
		SignerInfos:      []SignerInfo{signerInfo},
	}
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, err
	}
	var taggedBytes []byte
	taggedBytes = append(taggedBytes, 0xA0, 0x80)
	taggedBytes = append(taggedBytes, signedDataBytes...)
	taggedBytes = append(taggedBytes, 0x00, 0x00)
	finalContentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: OidSignedDataSM2,
		Content:     asn1.RawValue{FullBytes: taggedBytes},
	}
	return asn1.Marshal(finalContentInfo)
}

func Enveloped(encCert *x509.Certificate, plainData []byte) ([]byte, error) {
	sm4Key := make([]byte, 16)
	if _, err := rand.Read(sm4Key); err != nil {
		return nil, err
	}

	var sm2PubKey *sm2.PublicKey
	switch pub := encCert.PublicKey.(type) {
	case *sm2.PublicKey:
		sm2PubKey = pub
	case *ecdsa.PublicKey:
		sm2PubKey = &sm2.PublicKey{Curve: pub.Curve, X: pub.X, Y: pub.Y}
	default:
		return nil, fmt.Errorf("不支持的加密证书公钥类型: %T", encCert.PublicKey)
	}

	encryptMode := sm2.C1C3C2
	encryptedSm4Key_raw, err := sm2.Encrypt(sm2PubKey, sm4Key, rand.Reader, encryptMode)
	if err != nil {
		return nil, err
	}

	encryptedSm4Key_der, err := encodeSM2CipherToDER(encryptedSm4Key_raw)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	paddedData := pkcs7pad(plainData, sm4.BlockSize)
	block, err := sm4.NewCipher(sm4Key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(paddedData))
	mode.CryptBlocks(encryptedData, paddedData)

	var nullParam asn1.RawValue
	nullParam.Tag = asn1.TagNull
	ivParams, _ := asn1.Marshal(iv)

	recipientInfo := RecipientInfo{
		Version: 0,
		IssuerAndSerialNumber: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: encCert.RawIssuer},
			SerialNumber: encCert.SerialNumber,
		},
		KeyEncryptionAlgorithm: AlgorithmIdentifier{Algorithm: OidSM2Encrypt, Parameters: nullParam},
		EncryptedKey:           encryptedSm4Key_der,
	}
	encryptedContentInfo := EncryptedContentInfo{
		ContentType: OidData,
		ContentEncryptionAlgorithm: AlgorithmIdentifier{
			// 关键修正：使用Java端期望的通用SM4 OID
			Algorithm:  OidSM4,
			Parameters: asn1.RawValue{FullBytes: ivParams},
		},
		EncryptedContent: encryptedData,
	}
	envelopedData := EnvelopedData{
		Version:              0,
		RecipientInfos:       []RecipientInfo{recipientInfo},
		EncryptedContentInfo: encryptedContentInfo,
	}

	envelopedDataBytes, err := asn1.Marshal(envelopedData)
	if err != nil {
		return nil, err
	}

	var taggedBytes []byte
	taggedBytes = append(taggedBytes, 0xA0, 0x80)
	taggedBytes = append(taggedBytes, envelopedDataBytes...)
	taggedBytes = append(taggedBytes, 0x00, 0x00)

	finalContentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: OidEnvelopedData,
		Content:     asn1.RawValue{FullBytes: taggedBytes},
	}
	return asn1.Marshal(finalContentInfo)
}

func pkcs7pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func encodeSM2CipherToDER(rawCipher []byte) ([]byte, error) {
	const pubKeyLen = 64
	const digestLen = 32
	if len(rawCipher) <= 1+pubKeyLen+digestLen {
		return nil, errors.New("无效的SM2原始密文长度")
	}
	if rawCipher[0] != 0x04 {
		return nil, errors.New("无效的SM2公钥压缩位，必须为0x04")
	}

	pos := 1
	x := new(big.Int).SetBytes(rawCipher[pos : pos+pubKeyLen/2])
	pos += pubKeyLen / 2
	y := new(big.Int).SetBytes(rawCipher[pos : pos+pubKeyLen/2])
	pos += pubKeyLen / 2

	c3 := rawCipher[pos : pos+digestLen]
	pos += digestLen
	c2 := rawCipher[pos:]

	asn1Cipher := sm2CipherASN1{X: x, Y: y, C3: c3, C2: c2}
	return asn1.Marshal(asn1Cipher)
}
