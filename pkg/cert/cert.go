package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"time"

	"github.com/0siriz/keyweaver/pkg/models"
	"github.com/0siriz/keyweaver/pkg/storage"
)

func CreateCAs(config models.CAConfig) error {
	for name, ca := range config.CAs {
		publicKey, privateKey, err := generateKeypair()
		if err != nil {
			return err
		}
		
		err = saveKeypair(publicKey, privateKey, filepath.Join(config.OutputDirectory, name))
		if err != nil {
			return err
		}

		certificateBytes, err := CreateRootCert(
			ca.CommonName,
			ca.Organization,
			ca.Country,
			ca.ValidityDays,
			privateKey,
			publicKey)
		if err != nil {
			return err
		}

		err = saveCertificate(certificateBytes, filepath.Join(config.OutputDirectory, name))
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(certificateBytes)
		if err != nil {
			return err
		}

		err = createIssuedCAs(ca.IssuedCAs, config.OutputDirectory, privateKey, certificate)
		if err != nil {
			return err
		}
	}

	return nil
}

func createIssuedCAs(issuedCAs map[string]models.CADetails, outputDirectory string, parentPrivateKey ed25519.PrivateKey, parentCertificate *x509.Certificate) error {
	for name, ca := range issuedCAs {
		publicKey, privateKey, err := generateKeypair()
		if err != nil {
			return err
		}

		err = saveKeypair(publicKey, privateKey, filepath.Join(outputDirectory, name))
		if err != nil {
			return err
		}

		certificateBytes, err := CreateCACert(
			ca.CommonName,
			ca.Organization,
			ca.Country,
			ca.ValidityDays,
			privateKey,
			publicKey,
			parentPrivateKey,
			parentCertificate)
		if err != nil {
			return err
		}


		err = saveCertificate(certificateBytes, filepath.Join(outputDirectory, name))
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(certificateBytes)
		if err != nil {
			return err
		}

		err = createIssuedCAs(ca.IssuedCAs, outputDirectory, privateKey, certificate)
		if err != nil {
			return err
		}
	}

	return nil
}

func generateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return serialNumber, err
	}

	return serialNumber, nil
}

func saveKeypair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, outputDirectory string) error {
	marshalledPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	marshalledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	publicKeyFile := storage.File{
		FileName:  "public.pem",
		Directory: outputDirectory,
		FileType:  storage.FileTypePublicKey,
		FileMode:  0644,
		Data:      marshalledPublicKey,
	}
	privateKeyFile := storage.File{
		FileName:  "private.pem",
		Directory: outputDirectory,
		FileType:  storage.FileTypePrivateKey,
		FileMode:  0600,
		Data:      marshalledPrivateKey,
	}

	err = storage.SaveFile(privateKeyFile)
	if err != nil {
		return err
	}
	err = storage.SaveFile(publicKeyFile)
	if err != nil {
		return err
	}

	return nil
}

func saveCertificate(certificateBytes []byte, outputDirectory string) error {
	certificateFile := storage.File{
		FileName:  "certificate.crt",
		Directory: outputDirectory,
		FileType:  storage.FileTypeCertificate,
		FileMode:  0644,
		Data:      certificateBytes,
	}


	err := storage.SaveFile(certificateFile)
	if err != nil {
		return err
	}

	return nil
}

func CreateRootCert(
	commonName,
	organization,
	country string,
	validDays int,
	privateKey ed25519.PrivateKey,
	publicKey ed25519.PublicKey) ([]byte, error) {
	certificateBytes, err := CreateCACert(
		commonName,
		organization,
		country,
		validDays,
		privateKey,
		publicKey,
		nil,
		nil)

	return certificateBytes, err
}

func CreateCACert(
	commonName,
	organization,
	country string,
	validDays int,
	privateKey ed25519.PrivateKey,
	publicKey ed25519.PublicKey,
	parentPrivateKey ed25519.PrivateKey,
	parentCertificate *x509.Certificate) ([]byte, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	certificate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{country},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	signingPrivateKey := privateKey
	if parentPrivateKey != nil {
		signingPrivateKey = parentPrivateKey
	}
	signingCertificate := certificate
	if parentCertificate != nil {
		signingCertificate = parentCertificate
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, certificate, signingCertificate, publicKey, signingPrivateKey)
	if err != nil {
		return nil, err
	}

	return certificateBytes, nil
}
