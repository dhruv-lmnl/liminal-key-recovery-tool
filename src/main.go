package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"gitlab.com/sepior/ers-lib/ers"
	"gitlab.com/sepior/ers-lib/math"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/term"
)

type TSMCredentials struct {
	ClientId     string
	ClientSecret string
	UserID       string
	Password     string
	Url          string
	TSMPublicKey string
}

type RecoveryInfo struct {
	EcdsaRecoveryInfo string `json:"ecdsaRecoveryInfo"`
	EcdsaPublicKey    string `json:"ecdsaPublicKey"`
	EddsaRecoveryInfo string `json:"eddsaRecoveryInfo"`
	EddsaPublicKey    string `json:"eddsaPublicKey"`
}

func main() {
	fmt.Println("Welcome to Liminal Key Recovery Manager v0.0.1" +
		"\nYou should have received this tool as part of your onboarding from the Liminal team. Do not use any other binaries or tools.\n\n" +
		"WARNING: DO NOT USE RECOVERY OPTIONS ON AN ONLINE MACHINE.\n\n" +
		"This tool allows you to generate a recovery key pair and recovery package. It also enables you to perform recovery of your private backup key using your recovery package in an offline machine mode.\n\n" +
		"Recovery Key Pair - The recovery key pair is used to encrypt your recovery package. The recovery key pair contains a public key and private key encrypted by your passphrase. You must securely backup the recovery key pair files and the passphrase you provided to encrypt it. The recovery key pair must be generated by the owner of the account. They can safely share the recovery key pair's public key with the person generating the recovery package.\n\n" +
		"Recovery Package - The recovery package contains key material for your digital assets. This package allows you to access key material in an offline mode without Liminal or any other third party. The recovery package is encrypted using the public key from the recovery key pair, which ensures that only the person who generated the recovery key pair can decrypt the recovery package.\n\n" +
		"Private Backup Key - The Private Backup Key is the master private key for your digital assets, safely stored in encrypted form within your Recovery Package. You have two private backup keys: ECDSA and EDDSA. ECDSA private backup keys are used for protocols like Bitcoin, Ethereum, Tron, and similar ones. EDDSA private backup keys are used for protocols like Solana, Cardano, Cosmos, and similar ones.\n\n" +
		"Please press Enter to continue to the options...")
	var input string
	fmt.Scanln(&input)

	fmt.Println("Please select option.\n" +
		"1. Create a Recovery Key Pair - Generate a recovery key pair consisting of a public key and a private key. The recovery key pair is used to encrypt the recovery package. It requires a passphrase to encrypt the private key of the recovery key pair. Both the recovery key pair files and the passphrase must be securely backed up.\n" +
		"2. Create a Recovery Package - Generate a recovery package containing the private backup keys for your digital assets. This process requires the public key of the recovery key pair. The recovery package is generated and encrypted using the public key from the recovery key pair. It is essential to securely back up this package.\n" +
		"3. Verify the recovery key pair public key - Verify the public key file of the recovery key pair. This option should be used to confirm the validity of the recovery key pair's public key, especially when the key pair is generated by someone other than the owner. To perform this verification, you will need the recovery key pair's public key and access to the corresponding private key, both of which should be located in the same folder.\n" +
		"4. [OFFLINE] Verify the recovery package - Please use this option exclusively in offline mode to verify the accuracy of the recovery package. This procedure necessitates having the recovery package, the private key file of the recovery key pair, and the passphrase for the recovery key. Other option is to verify recovery package with HSM token.\n" +
		"5. [OFFLINE] Reveal the ECDSA Private Backup Key - Please utilize this option solely in an offline mode. This process requires the recovery package, the recovery key pair's private key file, and the recovery key passphrase. It reveals the ECDSA private backup key, which facilitates the recovery of digital assets from protocols like Bitcoin, Ethereum, and Polygon.\n" +
		"6. [OFFLINE] Reveal the EDDSA Private Backup Key - Please use this option exclusively in offline mode. This process requires the recovery package, the private key file of the recovery key pair, and the recovery key passphrase. It unveils the EDDSA private backup key, enabling the recovery of digital assets from protocols such as Solana and Cardano.\n" +
		"7. [OFFLINE] Export encrypted mnemonic phrase - Please use this option exclusively in offline mode to encrypt and export your 12/24 word mnemonic seed phrase\n" +
		"8. Export HSM public key - Reveal and export the public key of the HSM token\n" +
		"9. [OFFLINE] Coincover Backup & Recovery - Please use this option to encrypt backup data with Coincover public key and store it in Coincover server. Other option is to recover backup data from Coincover.",
	)

	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Println("Invalid input")
		log.Fatal(err)
	}

	if input == "1" {
		fmt.Println("Please select Key Pair generation option (1/2)\n" +
			"1. Generate using pkcs11 token.\n" +
			"2. Generate in memory / file.",
		)
		_, err = fmt.Scanln(&input)
		if err != nil {
			log.Println("Invalid input")
			log.Fatal(err)
		}

		if input == "1" {
			GenerateRsaKeypair()
		} else if input == "2" {
			startGeneratingRSAKey()
		} else {
			log.Fatal("Invalid choice")
		}
	} else if input == "2" {
		startGeneratingRecoveryInfo()
	} else if input == "3" {
		verifyRSAKey()
	} else if input == "4" {
		verifyRecoveryPackage()
	} else if input == "5" {
		startRecoveringECDSAPrivateKey()
	} else if input == "6" {
		startRecoveringEDDSAPrivateKey()
	} else if input == "7" {
		StartMnemonicRecovery()
	} else if input == "8" {
		ExportPublicKey()
	} else if input == "9" {
		input = TakeInput("Please select Coincover option (1/2)\n1. Perform Backup\n2. Perform Recovery")
		if input == "1" {
			CoincoverBackup()
		} else if input == "2" {
			CoincoverRecovery()
		} else {
			log.Fatal("Invalid choice")
		}
	} else {
		log.Fatal("Invalid choice")
	}
}

func startGeneratingRecoveryInfo() {
	fmt.Println("Please provide secure credentials to connect to Liminal Express MPC server (TSM server for older versions)")
	var tsmCredentials TSMCredentials

	var input string
	fmt.Println("Enter Client ID:")

	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.ClientId = input
	fmt.Println("Enter Client Secret:")

	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.ClientSecret = input
	fmt.Println("Enter TSM URL:")

	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.Url = input

	fmt.Println("Enter TSM UserID:")

	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.UserID = input

	fmt.Println("Enter TSM Password:")

	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.Password = input

	fmt.Println("Enter TSM Public Key:")

	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	tsmCredentials.TSMPublicKey = input

	if tsmCredentials.Url == "" || tsmCredentials.Password == "" || tsmCredentials.UserID == "" || tsmCredentials.TSMPublicKey == "" {
		log.Fatal("Invalid TSM credentials")
	}

	rsaPublicKey, err := os.ReadFile("liminal-recovery-key-pair-public-key.pem")
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa public key")
	}

	block, _ := pem.Decode(rsaPublicKey)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "use ParsePKCS1PublicKey instead for this key format") {
			key, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				log.Println(err)
				log.Fatal("Error reading pkcs11 public key")
			}
		} else {
			log.Println(err)
			log.Fatal("Error reading public key")
		}
	}

	pubKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	nodes := []tsm.Node{
		tsm.NewURLNode(mustParseURL(tsmCredentials.Url), &tsm.PasswordAuthenticator{Username: tsmCredentials.UserID, Password: tsmCredentials.Password}),
	}

	client := tsm.NewClient([]tsm.Node{nodes[0]})
	ecdsaClient := tsm.NewECDSAClient(client)
	eddsaClient := tsm.NewEDDSAClient(client)

	sessionId := uuid.NewString()

	token, err := getAuth0Token(tsmCredentials.ClientId, tsmCredentials.ClientSecret)
	if err != nil {
		log.Println("Error getting oauth token")
		log.Fatal(err)
	}

	err = registerTenant(tsmCredentials.TSMPublicKey, -1, *token, sessionId)
	if err != nil {
		log.Println("Error registering tenant")
		log.Fatal(err)
	}

	ecdsaKeyId, eddsaKeyId, err := getAccountDetails(*token)

	var recoveryInformation1 [][]byte
	var recoveryInformation2 *string
	var ecdsaRecoveryInformation []byte
	var wg sync.WaitGroup
	recoveryInformationData := RecoveryInfo{}
	if *ecdsaKeyId != "" {
		wg.Add(1)
		go func() {
			recoveryInformation1, err = ecdsaClient.PartialRecoveryInfo(sessionId, *ecdsaKeyId, pubKey, []byte(""))
			if err != nil {
				log.Println("Error generating recovery info")
				log.Fatal(err)
			}
			wg.Done()
		}()

		wg.Add(1)
		go func() {
			recoveryInformation2, err = startLiminalRecoveryInfo(*ecdsaKeyId, *token, pubKey, sessionId)
			if err != nil {
				log.Println("Error starting liminal recovery info")
				log.Fatal(err)
			}
			wg.Done()
		}()

		wg.Wait()

		decodedRecoveryInformation, err := hex.DecodeString(*recoveryInformation2)
		if err != nil {
			log.Println("Error decoding recovery info")
			log.Fatal(err)
		}

		ecdsaRecoveryInformation, err = tsm.RecoveryInfoCombine([][]byte{recoveryInformation1[0], decodedRecoveryInformation}, pubKey, []byte(""))
		if err != nil {
			log.Println("Error combining recovery info")
			log.Fatal(err)
		}
		recoveryInformationData.EcdsaRecoveryInfo = hex.EncodeToString(ecdsaRecoveryInformation)
	} else {
		log.Println("No ecdsa key found. Skipping ecdsa recovery...")
	}

	if *eddsaKeyId != "" {
		sessionId = uuid.NewString()
		err = registerTenant(tsmCredentials.TSMPublicKey, -1, *token, sessionId)
		if err != nil {
			log.Println("Error registering tenant")
			log.Fatal(err)
		}

		wg.Add(1)
		go func() {
			recoveryInformation1, err = eddsaClient.PartialRecoveryInfo(sessionId, *eddsaKeyId, pubKey, []byte(""))
			if err != nil {
				log.Println("Error generating recovery info")
				log.Fatal(err)
			}
			wg.Done()
		}()

		wg.Add(1)
		go func() {
			recoveryInformation2, err = startLiminalRecoveryInfo(*eddsaKeyId, *token, pubKey, sessionId)
			if err != nil {
				log.Println("Error starting liminal recovery info")
				log.Fatal(err)
			}
			wg.Done()
		}()

		wg.Wait()

		decodedRecoveryInformation, err := hex.DecodeString(*recoveryInformation2)
		if err != nil {
			log.Println("Error decoding recovery info")
			log.Fatal(err)
		}
		eddsaRecoveryInformation, err := tsm.RecoveryInfoCombine([][]byte{recoveryInformation1[0], decodedRecoveryInformation}, pubKey, []byte(""))
		if err != nil {
			log.Println("Error combining recovery info")
			log.Println(err)
		}
		recoveryInformationData.EddsaRecoveryInfo = hex.EncodeToString(eddsaRecoveryInformation)
	} else {
		log.Println("No eddsa key found. Skipping eddsa recovery...")
	}

	ecdsaPublicKey, err := ecdsaClient.XPub(*ecdsaKeyId, []uint32{})
	if err != nil {
		log.Println("Error getting ecdsa public key")
		log.Fatal(err)
	}
	eddsaPublicKey, err := eddsaClient.PublicKey(*eddsaKeyId, []uint32{})
	if err != nil {
		log.Println("Error getting ecdsa public key")
		log.Fatal(err)
	}

	recoveryInformationData.EcdsaPublicKey = ecdsaPublicKey
	recoveryInformationData.EddsaPublicKey = hex.EncodeToString(eddsaPublicKey)

	recoveryInformationString, err := json.Marshal(recoveryInformationData)
	if err != nil {
		fmt.Printf("could not marshal json: %s\n", err)
		return
	}

	err = os.WriteFile("liminal-recovery-package", recoveryInformationString, 0644)
	if err != nil {
		log.Println("Error writing recovery info to file")
		log.Fatal(err)
	}

	fmt.Println("Recovery package generated successfully as liminal-recovery-package. This package must be backed up securely.")
}

func startRecoveringECDSAPrivateKey() {
	recoveryMethod := TakeInput("Please choose recovery method (1/2)\n1. Using RSA private key file\n2. Using HSM token")

	var key *rsa.PrivateKey

	var ersDecryptor ers.Decryptor
	var ersHsmHelper *ErsHsmHelper

	if recoveryMethod == "1" {
		rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}

		fmt.Println("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
			"Please make sure the recovery package file with name liminal-recovery-package and recovery key pair private key file with name liminal-recovery-key-pair-private-key is in the current folder.\n" +
			"Enter Recovery key pair passphrase")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
		input := string(bytepw)
		block, _ := pem.Decode(rsaPrivateKey)
		privbytes, err := x509.DecryptPEMBlock(block, []byte(input))
		if err != nil {
			log.Println(err)
			log.Fatal("Incorrect password")
		}
		key, err = x509.ParsePKCS1PrivateKey(privbytes)
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}
		ersDecryptor = ers.NewRSADecryptor(key)
	} else if recoveryMethod == "2" {
		ersHsmHelper = InitializeErsHsmHelper()
	} else {
		log.Fatal("Invalid choice")
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

	ecdsaRecoveryData, err := hex.DecodeString(recoveryInfo.EcdsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery package")
	}

	var privateKeyASN1, masterChainCode []byte

	if recoveryMethod == string(IN_FILE_PRIVATE_KEY) {
		_, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersDecryptor, []byte(""), ecdsaRecoveryData, []uint32{})
	} else {
		_, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersHsmHelper, []byte(""), ecdsaRecoveryData, []uint32{})
	}

	if err != nil {
		log.Fatal(err)
	}

	privateKeyProduction, err := encodeKey(false, true, privateKeyASN1, masterChainCode)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding private key")
	}

	plaintext := []byte(privateKeyProduction)
	var label []byte = nil

	var encryptedBytes []byte

	if recoveryMethod == string(IN_FILE_PRIVATE_KEY) {
		if key == nil {
			log.Fatal("Invalid private key")
		}

		encryptedBytes, err = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			&key.PublicKey,
			plaintext,
			label,
		)
	} else {
		encryptedBytes, err = ersHsmHelper.Encrypt(plaintext, label)
	}

	if err != nil {
		panic(err)
	}

	err = os.WriteFile("liminal-ecdsa-private-backup-key", encryptedBytes, 0644)
	if err != nil {
		log.Println("Error writing recovery info to file")
		log.Fatal(err)
	}

	var input string
	fmt.Println("Do you want to reveal the private key? (y/n)")
	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	if strings.ToLower(input) == "y" || strings.ToLower(input) == "yes" {
		fmt.Println("Derived ECDSA private backup key")
		fmt.Println(privateKeyProduction)
	}

}

func startRecoveringEDDSAPrivateKey() {
	recoveryMethod := TakeInput("Please choose recovery method (1/2)\n1. Using RSA private key file\n2. Using HSM token")

	var key *rsa.PrivateKey

	var ersDecryptor ers.Decryptor
	var ersHsmHelper *ErsHsmHelper

	if recoveryMethod == string(IN_FILE_PRIVATE_KEY) {
		rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}

		fmt.Println("WARNING: PERFORM THIS ACTION ONLY ON OFFLINE COMPUTER\n" +
			"Please make sure the recovery package file with name liminal-recovery-package and recovery key pair private key file with name liminal-recovery-key-pair-private-key is in the current folder.\n" +
			"Enter Recovery key pair passphrase")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
		input := string(bytepw)
		block, _ := pem.Decode(rsaPrivateKey)
		privbytes, err := x509.DecryptPEMBlock(block, []byte(input))
		if err != nil {
			log.Println(err)
			log.Fatal("Incorrect password")
		}
		key, err = x509.ParsePKCS1PrivateKey(privbytes)
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}
	} else if recoveryMethod == string(HSM_TOKEN) {
		ersHsmHelper = InitializeErsHsmHelper()
	} else {
		log.Fatal("Invalid choice")
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

	var input string
	fmt.Println("Enter BIP 32 Path (It looks like m/XX/YY/A/B/C)")
	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading input")
	}

	var chainpath []uint32

	bip32Path := strings.Split(input, "/")
	for i, value := range bip32Path {
		if i == 0 && value == "m" {
			continue
		}
		bipIndex, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			log.Println(err)
			log.Fatal("Invalid path")
		}
		chainpath = append(chainpath, uint32(bipIndex))
	}

	eddsaRecoveryData, err := hex.DecodeString(recoveryInfo.EddsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery info")
	}

	var ellipticCurve string
	var privateKeyASN1, masterChainCode []byte

	if recoveryMethod == string(IN_FILE_PRIVATE_KEY) {
		ellipticCurve, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersDecryptor, []byte(""), eddsaRecoveryData, chainpath)
	} else {
		ellipticCurve, privateKeyASN1, masterChainCode, err = ers.RecoverPrivateKey(ersHsmHelper, []byte(""), eddsaRecoveryData, chainpath)
	}
	if err != nil {
		log.Println("Error recovering eddsa private key")
		log.Fatal(err)
	}

	curve, err := math.NewCurve(ellipticCurve)
	privateKeyScalar := curve.NewScalarBytes(privateKeyASN1)
	publicKey := curve.G().Mul(privateKeyScalar)
	privateKeyProduction := hex.EncodeToString(privateKeyASN1)
	publicKeyProduction := hex.EncodeToString(publicKey.Encode())
	masterChainCodeProduction := hex.EncodeToString(masterChainCode)
	eddsaData := "Derived Private key\n" + privateKeyProduction + "\nMaster chain code" + masterChainCodeProduction

	plaintext := []byte(eddsaData)
	var label []byte = nil

	var encryptedBytes []byte

	if recoveryMethod == string(IN_FILE_PRIVATE_KEY) {
		encryptedBytes, err = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			&key.PublicKey,
			plaintext,
			label,
		)
	} else {
		encryptedBytes, err = ersHsmHelper.Encrypt(plaintext, label)
	}

	if err != nil {
		panic(err)
	}
	err = os.WriteFile("liminal-eddsa-private-backup-key", encryptedBytes, 0644)
	if err != nil {
		log.Println("Error writing recovery info to file")
		log.Fatal(err)
	}
	fmt.Println("Do you want to reveal the private key? (y/n)")
	_, err = fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
	}
	if strings.ToLower(input) == "y" || strings.ToLower(input) == "yes" {
		fmt.Println("Master chain code")
		fmt.Println(masterChainCodeProduction)
		fmt.Println("Derived EDDSA public backup key")
		fmt.Println(publicKeyProduction)
		fmt.Println("Derived EDDSA private backup key")
		fmt.Println(privateKeyProduction)
	}

}

func startGeneratingRSAKey() {
	fmt.Println("Enter Recovery key pair passphrase")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	input := string(bytepw)
	if input == "" {
		fmt.Println("Password cannot be empty")
		os.Exit(1)
	}
	fmt.Println("Confirm Password")
	bytepw2, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	input2 := string(bytepw2)
	if input2 != input {
		fmt.Println("Passwords do not match")
		os.Exit(1)
	}
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, privateKeyBlock.Type, privateKeyBlock.Bytes, []byte(input), x509.PEMCipherAES256)
	if err != nil {
		log.Fatal(err)
	}
	privatePem, err := os.Create("liminal-recovery-key-pair-private-key.pem")
	if err != nil {
		fmt.Printf("error creating private key: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, block)
	if err != nil {
		fmt.Printf("error encoding private key: %s \n", err)
		os.Exit(1)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error dumping public key: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("liminal-recovery-key-pair-public-key.pem")
	if err != nil {
		fmt.Printf("error creating public key: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error encoding public key: %s \n", err)
		os.Exit(1)
	}
	fmt.Println("Recovery Key Pair generated successfully. Recovery key pair files and passphrase must be backed up securely.")
}

func verifyRSAKey() {
	rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa private key")
	}

	rsaPublicKey, err := os.ReadFile("liminal-recovery-key-pair-public-key.pem")
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa private key")
	}

	block, _ := pem.Decode(rsaPublicKey)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Println(err)
		log.Fatal("Error reading rsa private key")
	}

	fmt.Println("Enter Recovery key pair passphrase")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	input := string(bytepw)
	if input == "" {
		fmt.Println("Password cannot be empty")
		os.Exit(1)
	}

	block, _ = pem.Decode(rsaPrivateKey)
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

	msg := []byte("liminal recovery key pair public key verification")

	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}
	fmt.Println("Key verification successful")
}

func verifyRecoveryPackage() {
	verifyMethod := TakeInput("Please choose verification method (1/2)\n1. Using RSA private key file\n2. Using HSM token")

	var ersDecryptor ers.Decryptor

	if verifyMethod == "1" {
		rsaPrivateKey, err := os.ReadFile("liminal-recovery-key-pair-private-key.pem")
		if err != nil {
			log.Println(err)
			log.Fatal("Error reading rsa private key")
		}

		fmt.Println("Enter Recovery key pair passphrase")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
		input := string(bytepw)
		if input == "" {
			fmt.Println("Password cannot be empty")
			os.Exit(1)
		}

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

		ersDecryptor = ers.NewRSADecryptor(key)
	} else if verifyMethod == "2" {
		ersDecryptor = InitializeErsHsmHelper()
	} else {
		log.Fatal("Invalid choice")
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

	ecdsaRecoveryData, err := hex.DecodeString(recoveryInfo.EcdsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery package")
	}
	ellipticCurve, privateKeyASN1, masterChainCode, err := ers.RecoverPrivateKey(ersDecryptor, []byte(""), ecdsaRecoveryData, []uint32{})
	if err != nil {
		log.Fatal(err)
	}
	curveName := "secp256k1"
	curve := curveFromName[curveName]

	recoveredPK := curve.g().mul(new(big.Int).SetBytes(privateKeyASN1))
	b, err := encodePoint(recoveredPK)

	publicKeyProduction, err := encodeKey(true, true, b, masterChainCode)

	if publicKeyProduction != recoveryInfo.EcdsaPublicKey {
		log.Fatal("Ecdsa public key mismatch")
	}
	eddsaRecoveryData, err := hex.DecodeString(recoveryInfo.EddsaRecoveryInfo)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decoding recovery info")
	}
	ellipticCurve, privateKeyASN1, _, err = ers.RecoverPrivateKey(ersDecryptor, []byte(""), eddsaRecoveryData, []uint32{})
	if err != nil {
		log.Fatal(err)
	}
	curve2, err := math.NewCurve(ellipticCurve)
	privateKeyScalar := curve2.NewScalarBytes(privateKeyASN1)
	publicKey := curve2.G().Mul(privateKeyScalar)
	publicKeyProduction = hex.EncodeToString(publicKey.Encode())
	if publicKeyProduction != recoveryInfo.EddsaPublicKey {
		log.Fatal("Eddsa public key mismatch")
	}
	fmt.Println("Recovery package verification successful")
}
