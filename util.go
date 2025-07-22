package gmsm_infosec_pkcs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	gmX509 "github.com/tjfoc/gmsm/x509"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"math/big"
)

func GetPrivateKeyFromString(hexKey string) (*sm2.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("私钥十六进制解码失败: %v", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("无效的私钥长度，必须是32字节")
	}
	privKey := new(sm2.PrivateKey)
	privKey.D = new(big.Int).SetBytes(keyBytes)
	privKey.Curve = sm2.P256Sm2()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.Curve.ScalarBaseMult(keyBytes)
	return privKey, nil
}

// ParseX509Certificate 是核心的解析函数，它接收证书的字节内容
func ParseX509Certificate(certBytes []byte) (*gmX509.Certificate, error) {
	// gmsm/x509 的解析器足够智能，可以同时处理PEM和DER格式
	cert, err := gmX509.ParseCertificate(certBytes)
	if err != nil {
		// 如果直接解析失败，有可能是标准的PEM格式，我们尝试显式解码后再解析
		block, _ := pem.Decode(certBytes)
		if block == nil {
			return nil, fmt.Errorf("证书文件既不是有效的DER格式，也不是PEM格式")
		}
		cert, err = gmX509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %v", err)
		}
	}
	return cert, nil
}

// GetX509CertificateFromFile 是一个便捷的辅助函数，供使用者方便地从文件加载
func GetX509CertificateFromFile(filePath string) (*gmX509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件 '%s' 失败: %v", filePath, err)
	}
	return ParseX509Certificate(certBytes)
}

// LoadPfxFromFile 从可能包含证书链的.pfx文件中加载客户端证书和私钥
func LoadPfxFromFile(pfxPath, password string) (tls.Certificate, error) {
	pfxBytes, err := ioutil.ReadFile(pfxPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("读取 PFX 文件失败: %w", err)
	}
	return ParsePfx(pfxBytes, password)
}

// ParsePfx 从可能包含证书链的.pfx文件中加载客户端证书和私钥
func ParsePfx(pfxBytes []byte, password string) (tls.Certificate, error) {

	// 1. 使用 ToPEM 将 PFX 中的所有对象（私钥、证书、CA链）都解码成 PEM 格式的块
	// 这个函数比 Decode 更灵活，可以处理包含多个证书的 PFX 文件
	pemBlocks, err := pkcs12.ToPEM(pfxBytes, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("解码 PFX 文件失败 (ToPEM): %w", err)
	}

	// 2. 遍历所有解码出的 PEM 块，从中找出私钥和证书
	var cert tls.Certificate
	for _, b := range pemBlocks {
		// 如果是私钥块，则添加到 cert.PrivateKey
		if b.Type == "PRIVATE KEY" {
			cert.PrivateKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				// 尝试其他私钥格式, e.g., PKCS#8
				key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
				if err != nil {
					return tls.Certificate{}, fmt.Errorf("解析 PFX 中的私钥失败: %w", err)
				}
				cert.PrivateKey = key
			}
		}
		// 如果是证书块，则添加到 cert.Certificate
		if b.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, b.Bytes)
		}
	}

	if cert.PrivateKey == nil {
		return tls.Certificate{}, fmt.Errorf("在 PFX 文件中未找到私钥")
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("在 PFX 文件中未找到证书")
	}

	// 3. 从解析出的第一个证书中填充 Leaf 字段，以便tls包使用
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("解析 PFX 中的叶证书失败: %w", err)
	}

	return cert, nil
}
