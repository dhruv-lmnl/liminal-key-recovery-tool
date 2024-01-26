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
	wordNum := getNumberOfWordsInMnemonic()
	mnemonic := getMnemonic(wordNum)
	verifyMnemonic(mnemonic)
	encryptedMnemonic := encryptMnemonicWithHsm(mnemonic)
	verifyGeneratedAddress(mnemonic, encryptedMnemonic)
}

func getNumberOfWordsInMnemonic() int {
	input := TakeInput("Please enter number of mnemonic words (12/24).")
	switch input {
	case "12", "24":
		wordNum, err := strconv.ParseInt(input, 10, 0)
		checkError(err, "Invalid input")
		return int(wordNum)
	default:
		log.Fatal("Invalid input")
		return 0
	}
}

func getMnemonic(wordNum int) []string {
	fmt.Println("Please enter mnemonic phrase. Press Enter after each word.")

	var mnemonic []string

	for i := 0; i < int(wordNum); i++ {
		mnemonic = append(mnemonic, TakeInput(""))
	}

	return mnemonic
}

func verifyMnemonic(mnemonic []string) {
	mnemonicPhrase := strings.Join(mnemonic, " ")

	if !bip39.IsMnemonicValid(mnemonicPhrase) {
		log.Fatal("Invalid mnemonic words entered")
	}

	fmt.Println("Verify mnemonic phrase, press Enter after each word.")
	for _, word := range mnemonic {
		if TakeInput("") != word {
			log.Fatal("Word does not match with previously entered value.")
		}
	}
}

func encryptMnemonicWithHsm(mnemonic []string) []byte {
	message := []byte(strings.Join(mnemonic, " "))

	path, pin, keyId, keyName, tokenLabel := GetHsmConfig()

	enc, err := EncryptMessage(path, keyId, keyName, pin, tokenLabel, message, false)
	checkError(err, "error encrypting mnemonic")

	dec, err := DecryptMessage(path, keyId, keyName, pin, tokenLabel, enc, false)
	checkError(err, "error verifying encrypted mnemonic")

	if !bytes.Equal(message, dec) {
		log.Fatal("error encrypted mnemonic mismatch")
	}

	return enc
}

func verifyGeneratedAddress(mnemonic []string, encryptedMnemonic []byte) {
	wallet, err := hdwallet.NewFromMnemonic(strings.Join(mnemonic, " "))
	if err != nil {
		log.Fatal(err)
	}

	dPath := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(dPath, false)
	if err != nil {
		log.Fatal(err)
	}

	input := TakeInput(fmt.Sprintf("Does your default account (at path m/44'/60'/0'/0/0) match following address (y/n): %s\n", account.Address.Hex()))

	if strings.ToLower(input) == "y" {
		file, err := os.Create("encrypted-mnemonic-phrase.txt")
		if err != nil {
			log.Fatal("error creating encrypted mnemonic file: ", err)
		}
		base64EncryptedMnemonic := base64.RawStdEncoding.EncodeToString(encryptedMnemonic)

		n, _ := file.WriteString(base64EncryptedMnemonic)
		file.Close()

		if len(base64EncryptedMnemonic) != n {
			log.Fatal("error creating encrypted mnemonic file mismatch")
		}
		fmt.Println("Address verified, file containing encrypted mnemonic words exported successfully at encrypted-mnemonic-phrase.txt")
	} else {
		log.Fatal("address verification failed")
	}
}
