package storage

import (
	"encoding/pem"
	"os"
	"path/filepath"
)

type FileType int

const (
	FileTypePrivateKey FileType = 1 << iota
	FileTypePublicKey
	FileTypeCertificate
)

type File struct {
	FileName string
	Directory string
	FileType FileType
	Data []byte
}

func SaveFile(f File) error {
	
	if _, err := os.Stat(f.Directory); os.IsNotExist(err) {
		err := os.MkdirAll(f.Directory, 0755)
		if err != nil {
			return err
		}
	}

	pemfile, err := os.Create(filepath.Join(f.Directory, f.FileName))
	if err != nil {
		return err
	}
	defer pemfile.Close()

	var pemBlock *pem.Block = nil

	switch f.FileType {
	case FileTypePublicKey:
		pemBlock = &pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: f.Data,
		}
	case FileTypePrivateKey:
		pemBlock = &pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: f.Data,
		}
	case FileTypeCertificate:
		pemBlock = &pem.Block{
			Type: "CERTIFICATE",
			Bytes: f.Data,
		}
	}

	err = pem.Encode(pemfile, pemBlock)
	if err != nil {
		return err
	}

	return nil
}
