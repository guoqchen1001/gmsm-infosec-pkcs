# GMSM Infosec PKCS#7 SDK for Go

[![Go Report Card](https://goreportcard.com/badge/github.com/guoqchen1001/gmsm-infosec-pkcs)](https://goreportcard.com/report/github.com/guoqchen1001/gmsm-infosec-pkcs)
[![GoDoc](https://godoc.org/github.com/guoqchen1001/gmsm-infosec-pkcs?status.svg)](https://pkg.go.dev/github.com/guoqchen1001/gmsm-infosec-pkcs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

一个用于在Go语言中，生成与特定金融安全Java SDK (`cn.com.infosec`) 兼容的国密（SM2/SM4）PKCS#7消息的模块。

## 解决的问题

在使用标准的Go国密库（如 `tjfoc/gmsm`）与某些金融机构提供的、基于 `cn.com.infosec` 库的Java后端进行接口对接时，会因双方在PKCS#7的ASN.1编码实现上的细微差异，导致加密和签名消息无法被对方正确识别。

本项目通过对这些差异点进行精确适配，封装了底层的复杂性，旨在帮助Go开发者快速、可靠地完成此类系统的集成工作，避免漫长而痛苦的联调过程。

## 核心特性

* **完整的业务封装**：提供了 `MakeMSEnvelope` (签名并加密) 和 `DecryptMSEnvelope` (解密并验签) 的高级API，与Java端业务逻辑完全对齐。
* **精确的ASN.1适配**：处理了与目标Java库在算法标识符(OID)、`NULL`参数、SM2密文结构等方面的差异。
* **BER编码兼容**：手动构建了Java端期望的BER风格不确定性长度标签，解决了`ClassCastException`等解析问题。
* **证书处理**：内置了对 `.cer` (PEM/DER) 和 `.pfx` (PKCS#12) 格式证书的加载和解析。
* **向后兼容**：项目基于 `go 1.11`，对旧有环境友好。

## 安装

```bash
go get [github.com/guoqchen1001/gmsm-infosec-pkcs](https://github.com/guoqchen1001/gmsm-infosec-pkcs)
```

## 使用示例

下面是一个完整的示例，演示了如何初始化客户端、生成请求、发送并处理响应。
```go
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	pkcs "github.com/guoqchen1001/gmsm-infosec-pkcs"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	/*------------------------------参数初始化----start-------------------------------*/
	fmt.Println("--- [Go] 参数初始化 ---")

	sslCertFile := flag.String("ssl-cert", "config/bank-cert/000-net-cert.pfx", "客户端网络证书 (pfx) 路径")
	sslCertPwd := flag.String("ssl-pwd", "11111111", "客户端网络证书密码")
	bankCertFile := flag.String("bank-cert", "config/bank-cert/822_cert.cer", "银行公钥证书路径")
	clientCertFile := flag.String("client-cert", "config/client-cert/cert.cer", "客户端签名证书路径")
	clientPrivateKeyFile := flag.String("client-key", "config/client-cert/sm2private.txt", "客户端私钥文件路径")

	// 关键修正：在所有 flag 定义之后，调用 flag.Parse() 来解析命令行传入的参数
	flag.Parse()

	// 加载银行加密/验签公钥证书
	bankCert, err := pkcs.GetX509CertificateFromFile(*bankCertFile)
	if err != nil {
		fmt.Printf("加载银行证书失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("银行证书加载成功")

	// 加载客户端签名公钥证书
	clientCert, err := pkcs.GetX509CertificateFromFile(*clientCertFile)
	if err != nil {
		fmt.Printf("加载客户端签名证书失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("客户端签名证书加载成功")

	// 加载客户端签名/解密私钥
	privateKeyBytes, err := ioutil.ReadFile(*clientPrivateKeyFile)
	if err != nil {
		fmt.Printf("读取客户端私钥文件失败: %v\n", err)
		os.Exit(1)
	}
	clientPrivateKey, err := pkcs.GetPrivateKeyFromString(strings.TrimSpace(string(privateKeyBytes)))
	if err != nil {
		fmt.Printf("加载客户端私钥失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("客户端私钥加载成功")

	// 加载用于 mTLS 的客户端网络证书和私钥
	tlsClientCert, err := pkcs.LoadPfxFromFile(*sslCertFile, *sslCertPwd)
	if err != nil {
		fmt.Printf("加载网络证书(PFX)失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("客户端网络证书(PFX)加载成功")

	// 配置支持 mTLS 的 HTTP 客户端
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsClientCert},
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	fmt.Println("mTLS HTTP 客户端配置成功")
	/*-----------------------------参数初始化----end-------------------------------*/

	/*-------------------------组装报文、发送请求----start--------------------------*/
	path := "/v1/payment/scanToPay"
	apiGateway := "https://open-api-uat.jsrcu.com:18092/open/api" + path

	// 请求报文体-根据实际api情况修改
	body := "{\"request\":{\"channelCode\":\"822\",\"channelDate\":\"20240117\",\"channelSeq\":\"123456789012345678901\",\"version\":\"\",\"apiFlag\":\"\",\"transType\":\"\",\"mchntCd\":\"312023581200106\",\"traceNo\":\"00020240124170608847731617060885\",\"outTradeNo\":\"20240126141759161000023W\",\"longitude\":\"118.7830\",\"deviceId\":\"U0002448\",\"latitude\":\"32.02763\"}}"

	// 1. 生成需要发送的加密签名报文
	envelopedStr, err := pkcs.MakeMSEnvelope(clientPrivateKey, bankCert, clientCert, body)
	if err != nil {
		fmt.Printf("生成请求报文失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 准备请求头-根据实际api情况修改
	headers := map[string]string{
		"X-Client-Id":     "2025042591320923MACC04YN5J000001",
		"X-Client-Secret": "SdQ684",
		"X-Timestamp":     "2024-01-18 14:14:14",
		"X-RequestId":     "s34jfgdsfs8e49ddsu9d8343eedre346",
		"Content-Type":    "application/json",
	}

	// 3. 发送 HTTP POST 请求
	fmt.Println("\n--- [Go] 发送POST请求至", apiGateway, "---")
	req, err := http.NewRequest("POST", apiGateway, strings.NewReader(envelopedStr))
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		os.Exit(1)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("发送HTTP请求失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应体失败: %v\n", err)
		os.Exit(1)
	}

	/*------------------------------处理响应----start-------------------------------*/
	fmt.Println("--- [Go] 收到响应 ---")
	fmt.Println("HTTP Status:", resp.Status)
	fmt.Println("原始响应体 (Base64):", string(respBody))

	// 4. 解密并验签响应报文
	if resp.StatusCode == http.StatusOK {
		plainText, err := pkcs.DecryptMSEnvelope(clientPrivateKey, bankCert, string(respBody))
		if err != nil {
			fmt.Printf("❌ 解密或验签响应失败: %v\n", err)
		} else {
			fmt.Println("✅ 响应报文成功解密并验签！")
			fmt.Println("最终原文:", plainText)
		}
	}
	/*------------------------------处理响应----end---------------------------------*/
}

```


## 兼容性细节

本库为了实现与 `cn.com.infosec` Java SDK的兼容，主要处理了以下技术细节：
* **算法标识符 (OID)**: 使用了目标Java库白名单中定义的特定OID，例如 `SM3withSM2` (`...501`) 和 `SM2Encrypt` (`...301.3`)。
* **ASN.1编码**:
    * 为所有 `AlgorithmIdentifier` 结构添加了 `NULL` 参数。
    * 将SM2密文（`EncryptedKey`）从 `tjfoc/gmsm` 的原始字节拼接格式，正确地编码为目标库期望的 `SEQUENCE { X, Y, C3, C2 }` 结构。
    * 在顶层 `ContentInfo` 结构中，手动构建了BER风格的“不确定性长度”标签 (`A0 80 ... 00 00`)，以解决目标库的解析问题。
* **证书处理**: 提供了对包含完整CA链的 `.pfx` 文件的灵活解析。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。