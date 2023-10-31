package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
	"gitlab.com/sepior/ers-lib/ers"
	"gitlab.com/sepior/ers-lib/math"
	"golang.org/x/term"
)

type ErsDecryptor struct{}

func FullHsmRecovery() {
	fmt.Println("Enter recovery package file name")
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Println("Invalid input")
		log.Fatal(err)
	}

	var bytepw []byte

	recoveryType := getRecoveryPackageType(input)
	if recoveryType == 1 {
		fmt.Println("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
			"Please make sure the recovery package file with name liminal-recovery-package and recovery key pair private key file with name liminal-recovery-key-pair-private-key is in the current folder.\n" +
			"Enter Recovery key pair passphrase")
		bytepw, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
	} else {
		fmt.Println("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
			"Enter Recovery key pair passphrase")
		bytepw, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
	}

	recoveryInfo, _, err := getRecoveryInfoFromPackage("ecdsa", recoveryType, input, bytepw)
	if err != nil {
		log.Fatal(err)
	}
	log.Info(recoveryInfo.EcdsaPublicKey)

	ersDecryptor := ErsDecryptor{}

	ecdsaRecoveryData, err := hex.DecodeString(recoveryInfo.EcdsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery package")
	}
	_, privateKeyASN1, masterChainCode, err := ers.RecoverPrivateKey(ersDecryptor, []byte(""), ecdsaRecoveryData, []uint32{})
	if err != nil {
		log.Fatal(err)
	}
	curveName := "secp256k1"
	curve := curveFromName[curveName]

	recoveredPK := curve.g().mul(new(big.Int).SetBytes(privateKeyASN1))
	b, _ := encodePoint(recoveredPK)

	publicKeyProduction, _ := encodeKey(true, true, b, masterChainCode)

	if publicKeyProduction != recoveryInfo.EcdsaPublicKey {
		log.Fatal("Ecdsa public key mismatch")
	}
	eddsaRecoveryData, err := hex.DecodeString(recoveryInfo.EddsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery info")
	}
	ellipticCurve, privateKeyASN1, _, err := ers.RecoverPrivateKey(ersDecryptor, []byte(""), eddsaRecoveryData, []uint32{})
	if err != nil {
		log.Fatal(err)
	}
	curve2, _ := math.NewCurve(ellipticCurve)
	privateKeyScalar := curve2.NewScalarBytes(privateKeyASN1)
	publicKey := curve2.G().Mul(privateKeyScalar)
	publicKeyProduction = hex.EncodeToString(publicKey.Encode())
	if publicKeyProduction != recoveryInfo.EddsaPublicKey {
		log.Fatal("Eddsa public key mismatch")
	}
	fmt.Println("Recovery package verification successful")
}

func (ersDecryptor ErsDecryptor) Decrypt(ciphertext, label []byte) (plaintext []byte, err error) {
	path := TakeInput("Please enter pkcs11 lib path")
	pin := TakeInput("Please enter user pin")

	var keyId, keyName string
	switch input := TakeInput("Please select option.\n" + "1. Enter key id\n" + "2. Enter key name"); input {
	case "1":
		keyId = TakeInput("Please enter key id")
	case "2":
		keyName = TakeInput("Please enter key name")
	default:
		log.Fatal("Invalid input")
		return nil, errors.New("invalid user input")
	}

	var tokenLabel string
	switch input := TakeInput("Please select option.\n" + "1. Enter token label\n" + "2. Skip"); input {
	case "1":
		tokenLabel = TakeInput("Enter token label")
	case "2":
	default:
		log.Fatal("Invalid input")
		return nil, errors.New("invalid user input")
	}

	return DecryptMessage(path, keyId, keyName, pin, tokenLabel, ciphertext)
}
