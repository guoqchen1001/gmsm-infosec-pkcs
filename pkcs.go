package gmsm_infosec_pkcs

import (
	"github.com/guoqchen1001/gmsm-infosec-pkcs/internal"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func MakeMSEnvelope(clientPrivateKey *sm2.PrivateKey, bankCert *x509.Certificate, clientCert *x509.Certificate, plainText string) (string, error) {
	return internal.MakeMSEnvelope(clientPrivateKey, bankCert, clientCert, plainText)
}

func DecryptMSEnvelope(clientPrivateKey *sm2.PrivateKey, bankCert *x509.Certificate, envelopedStr string) (string, error) {
	return internal.DecryptMSEnvelope(clientPrivateKey, bankCert, envelopedStr)
}
