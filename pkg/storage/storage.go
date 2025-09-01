package storage

import (
	"encoding/pem"
	"os"
	"path/filepath"
)

type FileType int

const (
	FileTypePrivateKey FileType = iota
	FileTypeEncryptedPrivateKey
	FileTypePublicKey
	FileTypeCertificate
)

var fileTypeName = map[FileType]string{
	FileTypePrivateKey:          "PRIVATE KEY",
	FileTypeEncryptedPrivateKey: "ENCRYPTED PRIVATE KEY",
	FileTypePublicKey:           "PUBLIC KEY",
	FileTypeCertificate:         "CERTIFICATE",
}

type File struct {
	FileName string
	Directory string
	FileType FileType
	FileMode os.FileMode
	Data []byte
}

func SaveFile(f File) error {
	
	if _, err := os.Stat(f.Directory); os.IsNotExist(err) {
		err := os.MkdirAll(f.Directory, 0755)
		if err != nil {
			return err
		}
	}

	var pemBlock *pem.Block = &pem.Block{
		Type: fileTypeName[f.FileType],
		Bytes: f.Data,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	err := os.WriteFile(filepath.Join(f.Directory, f.FileName), pemBytes, f.FileMode)
	if err != nil {
		return err
	}

	return nil
}
