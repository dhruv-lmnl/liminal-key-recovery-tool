package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type CoincoverClient struct {
	BaseUrl string
}

type PublicKeyBody struct {
	UserEmail string `json:"userEmail"`
	UserId    string `json:"userId"`
	WalletId  string `json:"walletId"`
}

type PublicKeyResponse struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
	UserEmail string `json:"userEmail"`
	UserId    string `json:"userId"`
	WalletId  string `json:"walletId"`
	Verified  bool   `json:"verified"`
}

type EncryptBody struct {
	Signature string `json:"signature"`
	Pub       string `json:"pub"`
	Plain     string `json:"plain"`
}

type EncryptResponse struct {
	Cipher string `json:"cipher"`
}

type DecryptBody struct {
	Priv   string `json:"priv"`
	Cipher string `json:"cipher"`
}

type DecryptResponse struct {
}

type StoreBody struct {
	EndUserId string `json:"endUserId"`
	Data      string `json:"data"`
	BackupKey string `json:"backupKey"`
}

func CoincoverBackup() {

	coincoverClient := CoincoverClient{
		BaseUrl: strings.TrimSuffix(TakeInput("Please enter coincover base url"), "/"),
	}

	publicKeyResponse, err := coincoverClient.GetPublicKey()
	handleError("failed to get coincover public key", err)

	encryptResponse, err := coincoverClient.Encrypt(publicKeyResponse)
	handleError("failed to encrypt with coincover public key", err)

	err = coincoverClient.Store(encryptResponse, publicKeyResponse)
	handleError("failed to store encrypted data with coincover", err)

	fmt.Println("\nFile encrypted and stored with Coincover successfully")
}

func CoincoverRecovery() {
	coincoverClient := CoincoverClient{
		BaseUrl: strings.TrimSuffix(TakeInput("Please enter coincover base url"), "/"),
	}

	decryptResponse, err := coincoverClient.Decrypt()
	handleError("failed to recover backup data", err)

	log.Println("decrypt response: ", decryptResponse)
}

func (c *CoincoverClient) GetPublicKey() (*PublicKeyResponse, error) {
	reqBody := PublicKeyBody{
		UserEmail: TakeInput("Please enter user email"),
		UserId:    TakeInput("Please enter user id"),
		WalletId:  TakeInput("Please enter wallet id"),
	}

	var publicKeyResponse PublicKeyResponse
	statusCode, err := c.processCoincoverCall("/encryption-key", reqBody, &publicKeyResponse)
	if err != nil {
		return nil, err
	}

	err = handleStatusCode(statusCode, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	if !publicKeyResponse.Verified {
		return nil, errors.New("verification failed")
	}

	return &publicKeyResponse, nil
}

func (c *CoincoverClient) Encrypt(publicKeyResponse *PublicKeyResponse) (*EncryptResponse, error) {
	fileName := TakeInput("Please enter name of encrypted file")
	fileData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	plainData := string(fileData)

	// 190 bytes is the limit in coincover docs
	// however upto 446 bytes was working during testing
	if len(plainData) > 446 {
		return nil, fmt.Errorf("file size should be less than 446 bytes")
	}

	reqBody := EncryptBody{
		Signature: publicKeyResponse.Signature,
		Pub:       publicKeyResponse.PublicKey,
		Plain:     plainData,
	}

	var encryptResponse EncryptResponse
	statusCode, err := c.processCoincoverCall("/encrypt-rsa", reqBody, &encryptResponse)
	if err != nil {
		return nil, err
	}

	err = handleStatusCode(statusCode, http.StatusOK)
	if err != nil {
		return nil, err
	}

	return &encryptResponse, nil
}

func (c *CoincoverClient) Store(encryptResponse *EncryptResponse, publicKeyResponse *PublicKeyResponse) error {
	reqBody := StoreBody{
		EndUserId: publicKeyResponse.UserId,
		Data:      encryptResponse.Cipher,
		BackupKey: publicKeyResponse.PublicKey,
	}

	statusCode, err := c.processCoincoverCall("/store", reqBody, nil)
	if err != nil {
		return err
	}

	err = handleStatusCode(statusCode, http.StatusCreated)
	if err != nil {
		return err
	}

	return nil
}

func (c *CoincoverClient) Decrypt() (*DecryptResponse, error) {
	privateKeyFilePath := TakeInput("Please enter private key file path")
	cipherFilePath := TakeInput("Please enter encrypted data file path")

	privateKeyData, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, err
	}

	cipherData, err := os.ReadFile(cipherFilePath)
	if err != nil {
		return nil, err
	}

	reqBody := DecryptBody{
		Priv:   string(privateKeyData),
		Cipher: string(cipherData),
	}

	var decryptResponse DecryptResponse
	statusCode, err := c.processCoincoverCall("/decrypt-rsa", reqBody, &decryptResponse)
	if err != nil {
		return nil, err
	}

	err = handleStatusCode(statusCode, http.StatusOK)
	if err != nil {
		return nil, err
	}

	return &decryptResponse, nil
}

func (c *CoincoverClient) processCoincoverCall(endpoint string, reqBody interface{}, target interface{}) (int, error) {
	reqData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, err
	}

	body, statusCode, err := makePostRequest(c.BaseUrl+endpoint, reqData)
	if err != nil {
		return 0, err
	}

	if len(body) > 0 && target != nil {
		err = json.Unmarshal(body, &target)
		if err != nil {
			return 0, err
		}
	}

	return statusCode, nil
}

func makePostRequest(url string, data []byte) ([]byte, int, error) {
	res, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	return body, res.StatusCode, nil
}

func handleStatusCode(statusCode, successCode int) error {
	if statusCode == http.StatusBadRequest {
		return errors.New("bad request")
	} else if statusCode == http.StatusInternalServerError {
		return errors.New("internal server error")
	} else if statusCode != successCode {
		return fmt.Errorf("request failed (%v)", statusCode)
	}

	return nil
}

func handleError(baseMsg string, err error) {
	if err != nil {
		log.Fatalf("%v: %v", baseMsg, err)
	}
}
