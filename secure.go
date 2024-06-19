package secure_transfer

import (
	"archive/zip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func GenerateKeypairIfNotExists(keyPath string, verbose bool) error {
	_, err := os.ReadFile(keyPath + "rsa.pub")
	_, err2 := os.ReadFile(keyPath + "rsa.pk")
	var privateKey *rsa.PrivateKey
	if err != nil && err2 != nil {
		if verbose {
			fmt.Println("Keys not found, generating...")
		}

		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			if verbose {
				fmt.Println("key-generation failed", err)
			}
			return err
		}

		_ = os.Mkdir(keyPath, os.ModeDir)

		err = os.WriteFile(keyPath+"rsa.pub", exportPublicKeyAsPemStr(&privateKey.PublicKey), 0777)
		if err != nil {
			if verbose {
				fmt.Println("cannot write public key to file", err)
			}
			return err
		}
		err = os.WriteFile(keyPath+"rsa.pk", exportPrivateKeyAsPemStr(privateKey), 0777)
		if err != nil {
			if verbose {
				fmt.Println("cannot write private key to file", err)
			}
			return err
		}
	} else if err != nil {
		if verbose {
			fmt.Println("Only public key is present - delete it and run again to generate new keypair!")
		}
		return err
	} else if err2 != nil {
		if verbose {
			fmt.Println("Only private key is present - delete it and run again to generate new keypair!")
		}
		return err2
	} else {
		if verbose {
			fmt.Println("Keys already present, doing nothing!")
		}
	}
	return nil
}

// EncryptFile encodes the file at filePath with the publicKey from publicKeyPath - this should be a foreign public key.
func EncryptFile(filePath, pubKeyPath string, verbose bool) error {
	pubPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		if verbose {
			fmt.Println("PublicKey of other Person not found, make sure the path/name is correct...")
		}
		return err
	}
	pubKey, err := importPublicKeyFromPem(pubPEM)
	if err != nil {
		if verbose {
			fmt.Println("import pub key error", err)
		}
		return err
	}

	_, pubKeyName := path.Split(pubKeyPath)
	pubKeyName = strings.TrimSuffix(pubKeyName, ".pub")
	archName := "crypt_" + pubKeyName + "_" + time.Now().Format("020106_150405") + ".zip"
	file, err := os.Create(archName)
	if err != nil {
		if verbose {
			fmt.Println("init zip err", err)
		}
		return err
	}
	defer file.Close()
	zipW := zip.NewWriter(file)
	defer zipW.Close()

	aesKey, err := createAESKey()
	if err != nil {
		if verbose {
			fmt.Println("unable to generate aes key:", err)
		}
		return err
	}

	fName, err := encodeFileAES(aesKey, filePath, zipW)
	if err != nil {
		if verbose {
			fmt.Println("unable to encode file:", err)
		}
		return err
	}

	err = encryptRSA(aesKey, pubKey, "encryptedKey", zipW)
	if err != nil {
		if verbose {
			fmt.Println("unable to encode aes key:", err)
		}
		return err
	}

	err = encryptRSA([]byte(fName), pubKey, "fileName", zipW)
	if err != nil {
		if verbose {
			fmt.Println("unable to encode aes key:", err)
		}
		return err
	}
	return nil
}

// DecryptFile decodes a file from and into folderPath, where encryptedFile.bin and encryptedKey.bin are expected,
// which should have been encoded with your publicKey.
func DecryptFile(archivePath, keyPath string, verbose bool) error {
	pkPEM, err := os.ReadFile(keyPath + "rsa.pk")
	if err != nil {
		if verbose {
			fmt.Println("could not find private-key")
		}
		return err
	}
	pubPEM, err := os.ReadFile(keyPath + "rsa.pub")
	if err != nil {
		if verbose {
			fmt.Println("could not find public-key")
		}
		return err
	}

	zipR, err := zip.OpenReader(archivePath)
	if err != nil {
		if verbose {
			fmt.Println("could not find archive file to decode")
		}
		return err
	}
	defer zipR.Close()
	var aesCrypt, fileCrypt, nameCrypt []byte
	for _, file := range zipR.File {
		f, err := file.Open()
		if err != nil {
			if verbose {
				fmt.Println("could not open encrypted key from archive")
			}
			return err
		}
		res, err := io.ReadAll(f)
		if err != nil {
			if verbose {
				fmt.Println("could not read encrypted key from archive")
			}
			return err
		}
		_ = f.Close()
		switch file.Name {
		case "encryptedKey.bin":
			aesCrypt = res
		case "encryptedFile.bin":
			fileCrypt = res
		case "fileName.bin":
			nameCrypt = res
		default:
			if verbose {
				fmt.Println("bad archive format, found non-parseable file", file.Name)
			}
		}
	}

	privateKey, err := importPrivateKeyFromPem(pkPEM)
	if err != nil {
		if verbose {
			fmt.Println("import pk error", err)
		}
		return err
	}
	//todo: this should be not necessary
	pub, err := importPublicKeyFromPem(pubPEM)
	if err != nil {
		if verbose {
			fmt.Println("import pub key error", err)
		}
		return err
	}
	privateKey.PublicKey = *pub

	aesKey, err := decryptRSA(importMsgFromPem(aesCrypt), privateKey)
	if err != nil {
		if verbose {
			fmt.Println("decode aes key error", err)
		}
		return err
	}

	fileName, err := decryptRSA(importMsgFromPem(nameCrypt), privateKey)
	if err != nil {
		if verbose {
			fmt.Println("decode file name error", err)
		}
		return err
	}

	err = decodeFile(aesKey, fileCrypt, string(fileName))
	if err != nil {
		if verbose {
			fmt.Println("decode file error", err)
		}
		return err
	}
	return nil
}

func encryptRSA(message []byte, key *rsa.PublicKey, name string, zipW *zip.Writer) error {

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		message,
		nil)
	if err != nil {
		return err
	}

	f, err := zipW.Create(name + ".bin")
	if err != nil {
		return err
	}
	_, err = f.Write(exportMsgAsPemStr(encryptedBytes, strings.ToUpper(name)))
	if err != nil {
		return err
	}

	return nil
}

func decryptRSA(cipher []byte, key *rsa.PrivateKey) ([]byte, error) {
	decryptedBytes, err := key.Decrypt(nil, cipher, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func encodeFileAES(key []byte, path string, zipW *zip.Writer) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	plainText, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	zf, err := zipW.Create("encryptedFile.bin")
	if err != nil {
		return "", err
	}
	_, err = zf.Write(cipherText)
	if err != nil {
		return "", err
	}

	return filepath.Base(f.Name()), nil
}

func createAESKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func decodeFile(aesKey, cipherText []byte, fileName string) error {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	err = os.WriteFile("decoded_"+fileName, plainText, 0777)
	if err != nil {
		return err
	}
	return nil
}

func exportPublicKeyAsPemStr(pubkey *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)})
}
func exportPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
}
func exportMsgAsPemStr(msg []byte, title string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: title, Bytes: msg})
}
func importPublicKeyFromPem(msg []byte) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode(msg)
	key, err := x509.ParsePKCS1PublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func importPrivateKeyFromPem(msg []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(msg)
	key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func importMsgFromPem(msg []byte) []byte {
	blk, _ := pem.Decode(msg)
	return blk.Bytes
}
