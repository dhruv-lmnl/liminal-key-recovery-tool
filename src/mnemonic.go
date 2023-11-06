package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

func StartMnemonicRecovery() {
	var input string

	var wordNum int64

	fmt.Println("Please enter number of mnemonic words (12 / 24).")
	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	switch input {
	case "12", "24":
		wordNum, err = strconv.ParseInt(input, 10, 0)
		if err != nil {
			log.Fatal("Invalid number entered")
		}
	default:
		log.Fatal("Invalid input")
	}

	fmt.Println("Please enter mnemonic phrase. Press Enter after each word.")

	var mnemonic []string // = strings.Split(m, " ")

	for i := 0; i < int(wordNum); i++ {
		_, err := fmt.Scanln(&input)
		if err != nil {
			if i == 12 {
				break
			} else {
				log.Fatal(err)
			}
		}

		mnemonic = append(mnemonic, input)
	}

	mnemonicPhrase := strings.Join(mnemonic, " ")

	if !bip39.IsMnemonicValid(mnemonicPhrase) {
		log.Fatal("Invalid mnemonic words entered")
	}

	fmt.Println("Verify mnemonic phrase, please enter again.")
	for i := 0; i < len(mnemonic); i++ {
		_, err := fmt.Scanln(&input)
		if err != nil {
			log.Fatal(err)
		}

		if input != mnemonic[i] {
			log.Fatal("Word does not match")
		}
	}

	message := []byte(mnemonicPhrase)

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
	}

	var tokenLabel string
	switch input := TakeInput("Please select option.\n" + "1. Enter token label\n" + "2. Skip"); input {
	case "1":
		tokenLabel = TakeInput("Enter token label")
	case "2":
	default:
		log.Fatal("Invalid input")
	}

	enc, _ := EncryptMessage(path, keyId, keyName, tokenLabel, message)

	base64EncryptedMnemonic := base64.RawStdEncoding.EncodeToString(enc)

	dec, _ := DecryptMessage(path, keyId, keyName, pin, tokenLabel, enc)

	if !bytes.Equal(message, dec) {
		log.Fatal("decrypted value does not match message")
	}

	wallet, err := hdwallet.NewFromMnemonic(mnemonicPhrase)
	if err != nil {
		log.Fatal(err)
	}

	dPath := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(dPath, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Does your default account match following address (y/n):", account.Address.Hex())
	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}

	if strings.ToLower(input) == "y" {
		file, err := os.Create("encrypted-base64-mnemonic-phrase.txt")
		if err != nil {
			log.Fatal("error creating encrypted mnemonic file: ", err)
		}
		n, _ := file.WriteString(base64EncryptedMnemonic)
		file.Close()
		if len(base64EncryptedMnemonic) != n {
			log.Fatal("error creating encrypted mnemonic file")
		}
		log.Info("address verified, encrypted file created")
	} else {
		log.Fatal("address verification failed")
	}
}
