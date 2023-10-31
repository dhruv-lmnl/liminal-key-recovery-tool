package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type KeyData struct {
	KeyId       string `json:"keyid"`
	Algorithm   string `json:"algorithm"`
	RecoveryKey string `json:"recoverykey"`
	PublicKey   string `json:"publickey"`
}

func getRecoveryInfoFromPackage(algorithm string, recoveryType int, input string, bytepw []byte) (*RecoveryInfo, *rsa.PrivateKey, error) {
	if recoveryType == 1 {
		rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}
		input := string(bytepw)
		block, _ := pem.Decode(rsaPrivateKey)
		privbytes, err := x509.DecryptPEMBlock(block, []byte(input))
		if err != nil {
			log.Println(err)
			log.Fatal("Incorrect password")
		}
		key, err := x509.ParsePKCS1PrivateKey(privbytes)
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}

		recoveryData, err := os.ReadFile("liminal-recovery-package")
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading recovery package")
		}
		var recoveryInfo RecoveryInfo
		err = json.Unmarshal(recoveryData, &recoveryInfo)
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading recovery package")
		}
		return &recoveryInfo, key, nil
	} else {
		backupFileData, privateKeyEnc, keysData := unzipRecoveryPackage(input)
		var backupDetails struct {
			Salt  string `json:"salt"`
			IV    string `json:"iv"`
			Round int64  `json:"round"`
		}
		err := json.Unmarshal(backupFileData, &backupDetails)
		if err != nil {
			log.Println("Error reading backup file details")
			log.Fatal(err)
		}
		dk := pbkdf2.Key(bytepw, []byte(backupDetails.Salt), int(backupDetails.Round), 32, sha1.New)
		ciphertext, err := base64.StdEncoding.DecodeString(string(privateKeyEnc))
		if err != nil {
			panic(err)
		}
		block, err := aes.NewCipher(dk)
		if err != nil {
			panic(err)
		}

		if len(ciphertext)%aes.BlockSize != 0 {
			panic("Invalid encrypted private key")
		}

		mode := cipher.NewCBCDecrypter(block, []byte(backupDetails.IV))
		mode.CryptBlocks(ciphertext, ciphertext)

		base64Priv := string(PKCS5Trimming(ciphertext))
		decodedPrivKey, err := base64.StdEncoding.DecodeString(base64Priv)
		if err != nil {
			log.Println("Invalid private key or incorrect password")
			log.Fatal(err)
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(decodedPrivKey)
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}

		keyList := getKeyList(algorithm, keysData)

		if len(keyList) == 0 {
			log.Println("No keys found")
			os.Exit(0)
			return nil, nil, nil
		} else if len(keyList) == 1 {
			recoveryData := getRecoveryDataForKey(keyList[0], keysData)
			return recoveryData, privateKey, nil
		} else {
			fmt.Println("Multiple ecdsa keys found. Please select the key to use for recovery")
			for i, key := range keyList {
				fmt.Printf("%d. %s\n", i+1, key)
			}
			var input int
			_, err := fmt.Scanln(&input)
			if err != nil {
				log.Println("Invalid input")
				log.Fatal(err)
			}
			if input > len(keyList) || input < 1 {
				log.Println("Invalid input")
				log.Fatal(err)
			}
			recoveryData := getRecoveryDataForKey(keyList[input-1], keysData)

			return recoveryData, privateKey, nil
		}
	}
}

func getRecoveryPackageType(name string) int {
	var recoveryType string

	fmt.Println("Please select backup type.\n" + "1. Server backup\n" + "2. Mobile backup")
	_, err := fmt.Scanln(&recoveryType)
	if err != nil {
		log.Fatal(err)
	}

	if recoveryType == "1" {
		return 1
	} else if recoveryType == "2" {
		return 2
	} else {
		log.Fatal("Invalid input")
		return 0
	}
}

func GetFileContentType(output *os.File) (string, error) {
	buf := make([]byte, 512)
	_, err := output.Read(buf)
	if err != nil {
		return "", err
	}
	// the function that actually does the trick
	contentType := http.DetectContentType(buf)
	return contentType, nil
}

func unzipRecoveryPackage(name string) ([]byte, []byte, []KeyData) {
	var backupDetails []byte
	var privateKey []byte
	var keysData []KeyData
	archive, err := zip.OpenReader(name)
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		if strings.Contains(f.Name, "__MACOSX") {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}

		if strings.Contains(f.Name, "details.json") {
			fileInArchive, err := f.Open()
			if err != nil {
				panic(err)
			}

			backupDetails, err = io.ReadAll(fileInArchive)
			if err != nil {
				log.Println(err)
				log.Fatal("Error reading file " + f.Name)
			}
			fileInArchive.Close()
		}

		if strings.Contains(f.Name, "encRSAPrivateKey.txt") {
			fileInArchive, err := f.Open()
			if err != nil {
				panic(err)
			}

			privateKey, err = io.ReadAll(fileInArchive)
			if err != nil {
				log.Println(err)
				log.Fatal("Error reading file " + f.Name)
			}
			fileInArchive.Close()
		}

		if strings.Contains(f.Name, "fullrecovery") {
			fileInArchive, err := f.Open()
			if err != nil {
				panic(err)
			}

			keyFile, err := io.ReadAll(fileInArchive)
			if err != nil {
				log.Println(err)
				log.Fatal("Error reading file " + f.Name)
			}
			fileInArchive.Close()
			var keyData KeyData
			err = json.Unmarshal(keyFile, &keyData)
			if err != nil {
				log.Println(err)
				log.Fatal("Error reading file " + f.Name)
			}
			keysData = append(keysData, keyData)
		}

	}
	return backupDetails, privateKey, keysData
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func getKeyList(algorithm string, keysData []KeyData) []string {
	var ecdsaKeyNames []string
	for _, keyData := range keysData {
		if keyData.Algorithm == algorithm {
			ecdsaKeyNames = append(ecdsaKeyNames, keyData.KeyId)
		}
	}
	return ecdsaKeyNames
}

func getRecoveryDataForKey(keyId string, keysData []KeyData) *RecoveryInfo {

	for _, keyData := range keysData {
		if keyData.KeyId == keyId {
			recoveryData := RecoveryInfo{}
			if keyData.Algorithm == "ecdsa" {
				recoveryData.EcdsaRecoveryInfo = keyData.RecoveryKey
				recoveryData.EcdsaPublicKey = keyData.PublicKey
			} else if keyData.Algorithm == "eddsa" {
				recoveryData.EddsaRecoveryInfo = keyData.RecoveryKey
				recoveryData.EddsaPublicKey = keyData.PublicKey
			}
			return &recoveryData
		}
	}

	log.Println("Invalid algorithm")
	os.Exit(0)
	return nil
}
