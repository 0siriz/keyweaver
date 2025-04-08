package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"time"

	"github.com/0siriz/keyweaver/pkg/models"
	"github.com/0siriz/keyweaver/pkg/storage"
)

func CreateCAs(config models.CAConfig) (err error) {
	for rootCAName, rootCA := range config.CAs {
		rootPrivateKey, rootPublicKey, err := generateKey(rootCA.KeySize)
		if err != nil {
			return err
		}

		rootCertificate, err := CreateRootCert(
			rootCA.CommonName,
			rootCA.Organization,
			rootCA.Country,
			rootCA.ValidityDays,
			rootPrivateKey,
			rootPublicKey)
		if err != nil {
			return err
		}

		privateKeyFile := storage.File{
			FileName: "key.pem",
			Directory: filepath.Join(config.OutputDir, rootCAName),
			FileType: storage.FileTypePrivateKey,
			Data: x509.MarshalPKCS1PrivateKey(rootPrivateKey),

		}
		publicKeyFile := storage.File{
			FileName: "key.pub",
			Directory: filepath.Join(config.OutputDir, rootCAName),
			FileType: storage.FileTypePublicKey,
			Data: x509.MarshalPKCS1PublicKey(rootPublicKey),
		}
		certFile := storage.File{
			FileName: "certificate.crt",
			Directory: filepath.Join(config.OutputDir, rootCAName),
			FileType: storage.FileTypeCertificate,
			Data: rootCertificate,
		}

		err = storage.SaveFile(privateKeyFile)
		if err != nil {
			return err
		}
		err = storage.SaveFile(publicKeyFile)
		if err != nil {
			return err
		}
		err = storage.SaveFile(certFile)
		if err != nil {
			return err
		}

		parsedCert, err := x509.ParseCertificate(rootCertificate)
		if err != nil {
			return err
		}

		err = createIssuedCAs(rootCA.IssuedCAs, config.OutputDir, rootPrivateKey, parsedCert)
		if err != nil {
			return err
		}
	}

	return nil
}

func createIssuedCAs(issuedCAs map[string]models.CADetails, directory string, parentPrivateKey any, parentCertificate *x509.Certificate) (err error) {
	for issuedCAName, issuedCA := range issuedCAs {
		issuedPrivateKey, issuedPublicKey, err := generateKey(issuedCA.KeySize)
		if err != nil {
			return err
		}

		issuedCertificate, err := CreateCACert(
			issuedCA.CommonName,
			issuedCA.Organization,
			issuedCA.Country,
			issuedCA.ValidityDays,
			issuedPrivateKey,
			issuedPublicKey,
			parentPrivateKey,
			parentCertificate)
		if err != nil {
			return err
		}
		
		privateKeyFile := storage.File{
			FileName: "key.pem",
			Directory: filepath.Join(directory, issuedCAName),
			FileType: storage.FileTypePrivateKey,
			Data: x509.MarshalPKCS1PrivateKey(issuedPrivateKey),

		}
		publicKeyFile := storage.File{
			FileName: "key.pub",
			Directory: filepath.Join(directory, issuedCAName),
			FileType: storage.FileTypePublicKey,
			Data: x509.MarshalPKCS1PublicKey(issuedPublicKey),
		}
		certFile := storage.File{
			FileName: "certificate.crt",
			Directory: filepath.Join(directory, issuedCAName),
			FileType: storage.FileTypeCertificate,
			Data: issuedCertificate,
		}

		err = storage.SaveFile(privateKeyFile)
		if err != nil {
			return err
		}
		err = storage.SaveFile(publicKeyFile)
		if err != nil {
			return err
		}
		err = storage.SaveFile(certFile)
		if err != nil {
			return err
		}

		parsedCert, err := x509.ParseCertificate(issuedCertificate)
		if err != nil {
			return err
		}
		
		err = createIssuedCAs(issuedCA.IssuedCAs, directory, issuedPrivateKey, parsedCert)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateKey(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if keySize == 0 {
		keySize = 4096
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

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
	publicKey any) (cert []byte, err error) {
	cert, err = CreateCACert(
		commonName,
		organization,
		country,
		validDays,
		privateKey,
		publicKey,
		nil,
		nil)

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
	parentCertificate *x509.Certificate) (cert []byte, err error) {
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
