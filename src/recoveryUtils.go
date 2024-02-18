package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"gitlab.com/sepior/ers-lib/ers"
	"gitlab.com/sepior/ers-lib/math"
	"golang.org/x/crypto/pbkdf2"
)

type KeyData struct {
	KeyId       string `json:"keyid"`
	Algorithm   string `json:"algorithm"`
	RecoveryKey string `json:"recoverykey"`
	PublicKey   string `json:"publickey"`
}

func handleRecoveryMethodAndType(algorithm string) (RecoveryMethod, *RecoveryInfo, *rsa.PublicKey, *ErsHsmHelper, ers.Decryptor) {
	recoveryType := getRecoveryPackageType()
	recoveryMethod := getRecoveryMethod(recoveryType)

	key := &rsa.PrivateKey{}
	recoveryInfo := &RecoveryInfo{}

	var ersDecryptor ers.Decryptor
	var ersHsmHelper *ErsHsmHelper

	if recoveryType == SERVER {
		recoveryInfo = getRecoveryInfoFromServerBackup()

		if recoveryMethod == LOCAL_PRIVATE_KEY {
			password := TakePasswordInput("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
				"Please make sure the recovery package file with name liminal-recovery-package and recovery key pair private key file with name liminal-recovery-key-pair-private-key is in the current folder.\n" +
				"Enter Recovery key pair passphrase")
			key = readPrivateKeyFromPemFile(password)
			ersDecryptor = ers.NewRSADecryptor(key)
		} else if recoveryMethod == HSM_TOKEN {
			ersHsmHelper = InitializeErsHsmHelper()
		} else if recoveryMethod == MOBILE_PRIVATE_KEY {
			log.Fatal("Mobile private key recovery method is not supported for server backup recovery")
		}
	} else if recoveryType == MOBILE {
		backupFileName := TakeInput("Enter recovery package file name")
		recoveryInfo = getRecoveryInfoFromMobileBackup(backupFileName, algorithm)

		if recoveryMethod == LOCAL_PRIVATE_KEY {
			password := TakePasswordInput("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
				"Enter Recovery key pair passphrase")
			key = readPrivateKeyFromPemFile(password)
			ersDecryptor = ers.NewRSADecryptor(key)
		} else if recoveryMethod == HSM_TOKEN {
			ersHsmHelper = InitializeErsHsmHelper()
		} else if recoveryMethod == MOBILE_PRIVATE_KEY {
			password := TakePasswordInput("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
				"Enter Recovery key pair passphrase")
			key = getPrivateKeyFromMobileBackup(backupFileName, password)
			ersDecryptor = ers.NewRSADecryptor(key)
		}
	}

	fmt.Println("\nProcessing recovery data, please wait for a response.")

	return recoveryMethod, recoveryInfo, &key.PublicKey, ersHsmHelper, ersDecryptor
}

func handleErsRecoverPrivateKey(recoveryMethod RecoveryMethod, ersHsmHelper *ErsHsmHelper, ersDecryptor ers.Decryptor, recoveryData []byte, chainPath []uint32) (string, []byte, []byte) {
	var ellipticCurve string
	var privateKeyASN1 []byte
	var masterChainCode []byte
	var err error

	if recoveryMethod == HSM_TOKEN && ersHsmHelper != nil {
		ellipticCurve, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersHsmHelper, []byte(""), recoveryData, chainPath)
	} else if ersDecryptor != nil {
		ellipticCurve, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersDecryptor, []byte(""), recoveryData, chainPath)
	} else {
		log.Fatal("ERS decryptor not found for recovery method")
	}

	if err != nil {
		log.Fatal(err)
	}

	return ellipticCurve, privateKeyASN1, masterChainCode
}

func handleEncryptRecoveredData(recoveryMethod RecoveryMethod, ersHsmHelper *ErsHsmHelper, rsaPublicKey *rsa.PublicKey, plainText []byte, label []byte) []byte {
	var encryptedBytes []byte
	var err error

	if recoveryMethod == HSM_TOKEN {
		encryptedBytes, err = ersHsmHelper.Encrypt(plainText, label)
	} else {
		if rsaPublicKey == nil {
			log.Fatal("Invalid private key")
		}

		encryptedBytes, err = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			rsaPublicKey,
			plainText,
			label,
		)
	}

	checkError(err, "Unable to encrypt recovered data")

	return encryptedBytes
}

func readPrivateKeyFromPemFile(password string) *rsa.PrivateKey {
	rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa private key")
	}
	block, _ := pem.Decode(rsaPrivateKey)
	privbytes, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		log.Println(err)
		log.Fatal("Incorrect password")
	}
	key, err := x509.ParsePKCS1PrivateKey(privbytes)
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa private key")
	}

	return key
}

func getRecoveryInfoFromServerBackup() *RecoveryInfo {
	recoveryData, err := os.ReadFile("liminal-recovery-package")
	checkError(err, "Error reading recovery package")

	recoveryInfo := &RecoveryInfo{}
	err = json.Unmarshal(recoveryData, recoveryInfo)
	checkError(err, "Error parsing recovery package data")

	return recoveryInfo
}

func getRecoveryInfoFromMobileBackup(backupFileName string, algorithm string) *RecoveryInfo {
	_, _, keysData := unzipRecoveryPackage(backupFileName)
	return getRecoveryInfoFromMobileKeysData(keysData, algorithm)
}

func getRecoveryInfoFromMobileKeysData(keysData []KeyData, algorithm string) *RecoveryInfo {
	recoveryInfo := &RecoveryInfo{}

	var algorithms []string
	if algorithm == "" {
		algorithms = append(algorithms, ECDSA, EDDSA)
	} else {
		algorithms = append(algorithms, algorithm)
	}

	for _, currentAlgorithm := range algorithms {
		keyIds := getAlgorithmKeyId(currentAlgorithm, keysData)

		if len(keyIds) == 0 {
			log.Fatalf("No keys found for %s algorithm", currentAlgorithm)
			return nil
		} else if len(keyIds) == 1 {
			algorithmRecoveryInfo := getRecoveryDataForKey(keyIds[0], keysData)
			if currentAlgorithm == ECDSA {
				recoveryInfo.EcdsaRecoveryInfo = algorithmRecoveryInfo.EcdsaRecoveryInfo
				recoveryInfo.EcdsaPublicKey = algorithmRecoveryInfo.EcdsaPublicKey
			} else if currentAlgorithm == EDDSA {
				recoveryInfo.EddsaRecoveryInfo = algorithmRecoveryInfo.EddsaRecoveryInfo
				recoveryInfo.EddsaPublicKey = algorithmRecoveryInfo.EddsaPublicKey
			}
		} else {
			fmt.Printf("Multiple %s keys found. Please select the key to use for recovery. (1-%d)\n", currentAlgorithm, len(keyIds))
			for i, key := range keyIds {
				fmt.Printf("%d. %s\n", i+1, key)
			}
			var input int
			_, err := fmt.Scanln(&input)
			if err != nil {
				log.Println("Invalid input")
				log.Fatal(err)
			}
			if input > len(keyIds) || input < 1 {
				log.Fatal("Invalid input")
			}
			algorithmRecoveryInfo := getRecoveryDataForKey(keyIds[input-1], keysData)
			if currentAlgorithm == ECDSA {
				recoveryInfo.EcdsaRecoveryInfo = algorithmRecoveryInfo.EcdsaRecoveryInfo
				recoveryInfo.EcdsaPublicKey = algorithmRecoveryInfo.EcdsaPublicKey
			} else if currentAlgorithm == EDDSA {
				recoveryInfo.EddsaRecoveryInfo = algorithmRecoveryInfo.EddsaRecoveryInfo
				recoveryInfo.EddsaPublicKey = algorithmRecoveryInfo.EddsaPublicKey
			}
		}
	}

	return recoveryInfo
}

func getPrivateKeyFromMobileBackup(backupFileName string, password string) *rsa.PrivateKey {
	backupFileData, privateKeyEnc, _ := unzipRecoveryPackage(backupFileName)
	return getPrivateKeyFromMobileBackupDataAndEncryptedPrivateKey(backupFileData, privateKeyEnc, password)
}

func getPrivateKeyFromMobileBackupDataAndEncryptedPrivateKey(backupFileData []byte, privateKeyEnc []byte, password string) *rsa.PrivateKey {
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
	dk := pbkdf2.Key([]byte(password), []byte(backupDetails.Salt), int(backupDetails.Round), 32, sha1.New)
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

	return privateKey
}

func getRecoveryPackageType() RecoveryType {
	recoveryType := TakeInput("Please select backup type.\n" + "1. Server backup\n" + "2. Mobile backup")

	if recoveryType == "1" {
		return SERVER
	} else if recoveryType == "2" {
		return MOBILE
	} else {
		log.Fatal("Invalid input")
		return RecoveryType(recoveryType)
	}
}

func getRecoveryMethod(recoveryType RecoveryType) RecoveryMethod {
	var recoveryMethod string
	if recoveryType == SERVER {
		recoveryMethod = TakeInput("Please choose recovery method (1/2)\n1. Using local RSA private key file\n2. Using HSM token")
	} else {
		recoveryMethod = TakeInput("Please choose recovery method (1/2/3)\n1. Using local RSA private key file\n2. Using HSM token\n3. Using encrypted private key file in mobile backup")
	}

	if recoveryMethod == "1" {
		return LOCAL_PRIVATE_KEY
	} else if recoveryMethod == "2" {
		return HSM_TOKEN
	} else if recoveryMethod == "3" && recoveryType == MOBILE {
		return MOBILE_PRIVATE_KEY
	} else {
		log.Fatal("Invalid input")
		return RecoveryMethod(recoveryMethod)
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

func getAlgorithmKeyId(algorithm string, keysData []KeyData) []string {
	var keyList []string
	for _, keyData := range keysData {
		if keyData.Algorithm == algorithm {
			keyList = append(keyList, keyData.KeyId)
		}
	}
	return keyList
}

func getRecoveryDataForKey(keyId string, keysData []KeyData) *RecoveryInfo {
	for _, keyData := range keysData {
		if keyData.KeyId == keyId {
			recoveryData := &RecoveryInfo{}
			if keyData.Algorithm == ECDSA {
				recoveryData.EcdsaRecoveryInfo = keyData.RecoveryKey
				recoveryData.EcdsaPublicKey = keyData.PublicKey
			} else if keyData.Algorithm == EDDSA {
				recoveryData.EddsaRecoveryInfo = keyData.RecoveryKey
				recoveryData.EddsaPublicKey = keyData.PublicKey
			}
			return recoveryData
		}
	}

	log.Fatal("Invalid algorithm")
	return nil
}

func verifyECDSAPublicKey(recoveryMethod RecoveryMethod, recoveryInfo *RecoveryInfo, ersHsmHelper *ErsHsmHelper, ersDecryptor ers.Decryptor) {
	ecdsaRecoveryData, err := hex.DecodeString(recoveryInfo.EcdsaRecoveryInfo)
	checkError(err, "Error decoding recovery package")

	ellipticCurve, privateKeyASN1, masterChainCode := handleErsRecoverPrivateKey(recoveryMethod, ersHsmHelper, ersDecryptor, ecdsaRecoveryData, []uint32{})

	curve, err := math.NewCurve(ellipticCurve)
	checkError(err, "Error creating new curve")

	privateMasterKey := curve.NewScalarBytes(privateKeyASN1)
	publicMasterKey := curve.G().Mul(privateMasterKey)

	if strings.HasPrefix(recoveryInfo.EcdsaPublicKey, "xpub") {
		verifyXpubPublicKey(recoveryInfo, privateKeyASN1, masterChainCode)
	} else {
		verifyHexPublicKey(recoveryInfo, publicMasterKey)
	}
}

func verifyXpubPublicKey(recoveryInfo *RecoveryInfo, privateKeyASN1 []byte, masterChainCode []byte) {
	curveName := SECP256K1
	curve := curveFromName[curveName]

	recoveredPK := curve.g().mul(new(big.Int).SetBytes(privateKeyASN1))
	b, err := encodePoint(recoveredPK)
	checkError(err, "Error decoding public key")

	publicKeyProduction, err := encodeKey(true, true, b, masterChainCode)
	checkError(err, "Error decoding public key")

	if publicKeyProduction != recoveryInfo.EcdsaPublicKey {
		log.Fatal("Error verifying ecdsa public key")
	}
}

func verifyHexPublicKey(recoveryInfo *RecoveryInfo, publicMasterKey math.Point) {
	asn1PublicKey, err := hex.DecodeString(recoveryInfo.EcdsaPublicKey)
	checkError(err, "Error decoding public key")

	parsedPublicKey, err := parseASN1PublicKey(asn1PublicKey)
	checkError(err, "Error parsing public key")

	publicKeyKeyFile := hex.EncodeToString(parsedPublicKey)
	publicKeyFromPrivateKey := hex.EncodeToString(publicMasterKey.Encode())

	if publicKeyKeyFile != publicKeyFromPrivateKey {
		log.Fatal("Error verifying ecdsa public key")
	}
}

func verifyEDDSAPublicKey(recoveryMethod RecoveryMethod, recoveryInfo *RecoveryInfo, ersHsmHelper *ErsHsmHelper, ersDecryptor ers.Decryptor) {
	eddsaRecoveryData, err := hex.DecodeString(recoveryInfo.EddsaRecoveryInfo)
	checkError(err, "Error decoding recovery info")

	ellipticCurve, privateKeyASN1, _ := handleErsRecoverPrivateKey(recoveryMethod, ersHsmHelper, ersDecryptor, eddsaRecoveryData, []uint32{})

	curve, err := math.NewCurve(ellipticCurve)
	checkError(err, "Error creating new curve")

	privateKeyScalar := curve.NewScalarBytes(privateKeyASN1)
	publicKey := curve.G().Mul(privateKeyScalar)
	publicKeyProduction := hex.EncodeToString(publicKey.Encode())

	if publicKeyProduction != strings.ToLower(recoveryInfo.EddsaPublicKey) {
		log.Fatal("Error verifying eddsa public key")
	}
}
