package internal

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
)

// DecryptMSEnvelope 封装了解密和验签的完整流程
func DecryptMSEnvelope(clientPrivateKey *sm2.PrivateKey, bankCert *x509.Certificate, envelopedStr string) (string, error) {

	// Base64 解码
	envelopedBytes, err := base64.StdEncoding.DecodeString(envelopedStr)
	if err != nil {
		return "", fmt.Errorf("Base64解码响应失败: %w", err)
	}

	// 解密
	signedBytes, err := Unenveloped(clientPrivateKey, envelopedBytes)
	if err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}

	// 验签
	plainData, err := VerifySigned(signedBytes, bankCert)
	if err != nil {
		return "", fmt.Errorf("验签失败: %w", err)
	}

	return string(plainData), nil
}

// decodeDERSM2Cipher 将标准的ASN.1 SEQUENCE格式的SM2密文，转换为gmsm库期望的原始字节拼接格式
func decodeDERSM2Cipher(derCipher []byte) ([]byte, error) {
	var asn1Cipher sm2CipherASN1
	if _, err := asn1.Unmarshal(derCipher, &asn1Cipher); err != nil {
		return nil, fmt.Errorf("反序列化SM2密文失败: %v", err)
	}

	xBytes := asn1Cipher.X.Bytes()
	yBytes := asn1Cipher.Y.Bytes()
	c3Bytes := asn1Cipher.C3
	c2Bytes := asn1Cipher.C2

	// 补齐X,Y坐标到32字节
	if n := len(xBytes); n < 32 {
		xBytes = append(make([]byte, 32-n), xBytes...)
	}
	if n := len(yBytes); n < 32 {
		yBytes = append(make([]byte, 32-n), yBytes...)
	}

	// 按照 C1C3C2 的顺序拼接
	rawCipher := []byte{0x04}
	rawCipher = append(rawCipher, xBytes...)
	rawCipher = append(rawCipher, yBytes...)
	rawCipher = append(rawCipher, c3Bytes...)
	rawCipher = append(rawCipher, c2Bytes...)
	return rawCipher, nil
}

// pkcs7unpad 实现PKCS#7去填充
func pkcs7unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密数据为空")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("无效的填充数据")
	}
	return data[:(length - unpadding)], nil
}

// Unenveloped 实现 unEnveloped 方法的Go版本
func Unenveloped(privateKey *sm2.PrivateKey, envelopedData []byte) ([]byte, error) {
	// 1. 解析顶层ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(envelopedData, &contentInfo); err != nil {
		return nil, fmt.Errorf("解析顶层ContentInfo失败: %v", err)
	}

	// 2. 解析EnvelopedData
	var data EnvelopedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &data); err != nil {
		// 尝试处理BER不确定长度编码
		var berContent []byte
		// BER indefinite-length SEQUENCEs are tagged 0xA0 0x80 ... 0x00 0x00
		if len(contentInfo.Content.Bytes) > 4 &&
			contentInfo.Content.Bytes[0] == 0xA0 && contentInfo.Content.Bytes[1] == 0x80 &&
			contentInfo.Content.Bytes[len(contentInfo.Content.Bytes)-2] == 0x00 &&
			contentInfo.Content.Bytes[len(contentInfo.Content.Bytes)-1] == 0x00 {
			berContent = contentInfo.Content.Bytes[2 : len(contentInfo.Content.Bytes)-2]
		} else {
			return nil, fmt.Errorf("解析EnvelopedData失败: %v", err)
		}

		if _, err := asn1.Unmarshal(berContent, &data); err != nil {
			return nil, fmt.Errorf("解析BER EnvelopedData失败: %v", err)
		}
	}

	if len(data.RecipientInfos) == 0 {
		return nil, errors.New("未找到RecipientInfo")
	}

	// 3. 提取并转换加密的SM4密钥
	recipientInfo := data.RecipientInfos[0]
	encryptedSm4Key_der := recipientInfo.EncryptedKey
	encryptedSm4Key_raw, err := decodeDERSM2Cipher(encryptedSm4Key_der)
	if err != nil {
		return nil, err
	}

	// 4. 使用SM2私钥解密出SM4密钥
	sm4Key, err := sm2.Decrypt(privateKey, encryptedSm4Key_raw, sm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("SM2解密SM4密钥失败: %v", err)
	}

	// 5. 提取IV和加密的主体内容
	encryptedContentInfo := data.EncryptedContentInfo
	encryptedContent := encryptedContentInfo.EncryptedContent
	var iv []byte
	if encryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes != nil {
		if _, err := asn1.Unmarshal(encryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
			return nil, fmt.Errorf("解析IV失败: %v", err)
		}
	}

	// 6. 使用SM4-CBC解密主体内容
	block, err := sm4.NewCipher(sm4Key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(encryptedContent))
	mode.CryptBlocks(decryptedData, encryptedContent)

	// 7. 去除填充，返回最终原文
	return pkcs7unpad(decryptedData)
}

// VerifySigned 实现了 verifySigned 方法的Go版本
// signedDataBytes: 已签名的PKCS#7数据 (通常是Unenveloped的结果)
// trustedSignCert: 用于验证的、可信的签名者证书
func VerifySigned(signedDataBytes []byte, trustedSignCert *x509.Certificate) ([]byte, error) {
	// 1. 解析顶层ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(signedDataBytes, &contentInfo); err != nil {
		// 尝试处理BER不确定长度编码
		if len(signedDataBytes) > 4 &&
			signedDataBytes[0] == 0xA0 && signedDataBytes[1] == 0x80 &&
			signedDataBytes[len(signedDataBytes)-2] == 0x00 &&
			signedDataBytes[len(signedDataBytes)-1] == 0x00 {
			// 如果是BER编码，我们只需要里面的内容
			signedDataBytes = signedDataBytes[2 : len(signedDataBytes)-2]
		} else {
			return nil, fmt.Errorf("解析顶层ContentInfo失败: %v", err)
		}
	} else {
		// 如果是DER编码，内容在 explicit tag 内部
		signedDataBytes = contentInfo.Content.Bytes
	}

	// 2. 解析SignedData
	var signedData SignedData
	if _, err := asn1.Unmarshal(signedDataBytes, &signedData); err != nil {
		return nil, fmt.Errorf("解析SignedData失败: %v", err)
	}

	if len(signedData.SignerInfos) != 1 {
		return nil, errors.New("仅支持一个签名者")
	}

	// 3. 提取核心数据
	signerInfo := signedData.SignerInfos[0]
	contentData := signedData.EncapContentInfo.Content
	signature := signerInfo.EncryptedDigest

	// 4. 从数据包中查找签名者证书
	var signerCert *x509.Certificate
	foundCert := false
	for _, rawCert := range signedData.Certificates {
		cert, err := x509.ParseCertificate(rawCert.FullBytes)
		if err != nil {
			continue // 解析下一个
		}
		// 通过颁发者和序列号匹配证书
		if bytes.Equal(cert.RawIssuer, signerInfo.IssuerAndSerialNumber.Issuer.FullBytes) &&
			cert.SerialNumber.Cmp(signerInfo.IssuerAndSerialNumber.SerialNumber) == 0 {
			signerCert = cert
			foundCert = true
			break
		}
	}

	if !foundCert {
		return nil, errors.New("在签名数据中未找到匹配的签名证书")
	}

	// (可选) 进一步校验找到的证书是否与我们信任的证书一致
	if !bytes.Equal(signerCert.Raw, trustedSignCert.Raw) {
		// 这里可以根据业务需求决定是报错还是继续
		fmt.Println("警告: 签名数据中的证书与提供的可信证书不完全一致，但颁发者和序列号匹配。")
	}

	// 5. 健壮地处理公钥类型并执行SM2验签
	var sm2PubKey *sm2.PublicKey
	switch pub := signerCert.PublicKey.(type) {
	case *sm2.PublicKey:
		sm2PubKey = pub
	case *ecdsa.PublicKey:
		sm2PubKey = &sm2.PublicKey{Curve: pub.Curve, X: pub.X, Y: pub.Y}
	default:
		return nil, fmt.Errorf("不支持的签名证书公钥类型: %T", signerCert.PublicKey)
	}

	// Verify方法返回一个布尔值
	isValid := sm2PubKey.Verify(contentData, signature)
	if !isValid {
		return nil, errors.New("SM2签名验证失败")
	}

	// 6. 验签成功，返回原文
	return contentData, nil
}
