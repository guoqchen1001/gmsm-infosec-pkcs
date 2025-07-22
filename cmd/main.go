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
