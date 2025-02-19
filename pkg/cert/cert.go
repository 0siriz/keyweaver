package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func generateSerialNumber() (serialNumber *big.Int, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) 
	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return serialNumber, err
	}

	return serialNumber, nil
}

func CreateRootCert(
	commonName,
	organization,
	country string,
	validDays int,
	privateKey,
	publicKey any,
) (cert []byte, err error) {
	cert, err = CreateCACert(
		commonName,
		organization,
		country,
		validDays,
		privateKey,
		publicKey,
		nil,
		nil,
	)

	return cert, err
}

func CreateCACert(
	commonName,
	organization,
	country string,
	validDays int,
	privateKey,
	publicKey,
	parentPrivateKey any,
	parentCertificate *x509.Certificate,
) (cert []byte, err error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	caCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
			Organization: []string{organization},
			Country: []string{country},
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(0, 0, validDays),
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	signingPrivateKey := privateKey
	if parentPrivateKey != nil {
		signingPrivateKey = parentPrivateKey
	}
	signingCertificate := caCert
	if parentCertificate != nil {
		signingCertificate = parentCertificate
	}
	cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, publicKey, signingPrivateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
