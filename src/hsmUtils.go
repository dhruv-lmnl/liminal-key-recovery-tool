package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"syscall"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

/*
remember to defer destroy and finalize after calling this function
*/
func Init(path string) (*pkcs11.Ctx, error) {
	p := pkcs11.New(path)
	if err := p.Initialize(); err != nil {
		return nil, err
	}

	return p, nil
}

/*
remember to defer closeSession and logout after calling this function
*/
func openSession(p *pkcs11.Ctx, tokenLabel string, pin string) (pkcs11.SessionHandle, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return pkcs11.SessionHandle(0), err
	}

	if len(slots) == 0 {
		return pkcs11.SessionHandle(0), errors.New("unable to open session, slot list empty")
	}

	slotId := 0

	for i := 0; i < len(slots); i++ {
		if tokenLabel == "" {
			break
		}
		tokenInfo, err := p.GetTokenInfo(slots[i])
		if err != nil {
			return pkcs11.SessionHandle(0), err
		}
		if tokenLabel == tokenInfo.Label {
			slotId = i
			break
		}
	}

	session, err := p.OpenSession(
		slots[slotId],
		pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION,
	)
	if err != nil {
		return pkcs11.SessionHandle(0), err
	}

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return pkcs11.SessionHandle(0), err
	}

	return session, nil
}

func getPublicKeyTemplate(keyId, keyName string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
	}
}

func getPrivateKeyTemplate(keyId, keyName string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
	}
}

func getRsaKeypairGenerationMechanisms() []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
	}
}

func GenerateRsaKeypair() error {
	path := TakeInput("Please enter pkcs11 lib path")
	pin := TakePinInput("Please enter user pin")

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

	var recreate bool
	switch input := TakeInput("Please select option.\n" + "1. Recreate keypair, if existing found\n" + "2. Skip keypair generation, if existing found"); input {
	case "1":
		recreate = true
	case "2":
		recreate = false
	default:
		log.Fatal("Invalid input")
	}

	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pbks, err := getPublicObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}
	pvks, err := getPrivateObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}

	if len(pbks) > 0 && len(pvks) > 0 {
		if recreate {
			err = p.DestroyObject(session, pbks[0])
			if err != nil {
				log.Println(err)
				log.Fatal("Error generating rsa keypair")
				return err
			}
			err = p.DestroyObject(session, pvks[0])
			if err != nil {
				log.Println(err)
				log.Fatal("Error generating rsa keypair")
				return err
			}
		} else {
			log.Println("Existing keypair found, skipping keypair generation")
			return errors.New("existing keypair found with same key id/name")
		}
	}

	pbk, _, err := p.GenerateKeyPair(
		session,
		getRsaKeypairGenerationMechanisms(),
		getPublicKeyTemplate(keyId, keyName),
		getPrivateKeyTemplate(keyId, keyName),
	)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}

	pubkeyPem, err := getPublicKey(p, session, pbk)
	if err != nil {
		log.Println(err)
		log.Fatal("Error generating rsa keypair")
		return err
	}

	fmt.Println(pubkeyPem)

	err = SaveFile("liminal-recovery-key-pair-public-key.pem", pubkeyPem)
	if err != nil {
		log.Println(err)
		log.Fatal("Error exporting rsa keypair")
		return err
	}

	fmt.Println("RSA keypair generated successfully")

	return nil
}

func DeleteRsaKeypair() error {
	path := TakeInput("Please enter pkcs11 lib path")
	pin := TakePinInput("Please enter user pin")

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

	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pbks, err := getPublicObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error finding public object handle")
		return err
	}

	if len(pbks) == 0 {
		log.Println(err)
		log.Fatal("Error finding public object handle")
		return err
	}

	pvks, err := getPrivateObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}

	if len(pvks) == 0 {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}

	err = p.DestroyObject(session, pbks[0])
	if err != nil {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}

	err = p.DestroyObject(session, pvks[0])
	if err != nil {
		log.Println(err)
		log.Fatal("Error deleting rsa keypair")
		return err
	}

	fmt.Println("Successfully deleted public key object")

	return nil
}

func ExportPublicKey() error {
	path := TakeInput("Please enter pkcs11 lib path")
	pin := TakePinInput("Please enter user pin")

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

	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error exporting public key")
		return err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error exporting public key")
		return err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pbks, err := getPublicObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error exporting public key")
		return err
	}

	if len(pbks) == 0 {
		log.Println(err)
		log.Fatal("Error finding public object handle")
		return err
	}

	pubkeyPem, err := getPublicKey(p, session, pbks[0])
	if err != nil {
		log.Println(err)
		log.Fatal("Error exporting public key")
		return err
	}

	fmt.Printf("\n%v\n", pubkeyPem)

	if input := TakeInput("Export public key to file (y/n)"); strings.ToLower(input) == "y" {
		err = SaveFile("liminal-recovery-key-pair-public-key.pem", pubkeyPem)
		if err != nil {
			log.Println(err)
			log.Fatal("Error exporting public key")
			return err
		}

		fmt.Println("Public key exported successfully")
	}

	return nil
}

func SignMessage(path, keyId, keyName, pin, tokenLabel string, message []byte) ([]byte, error) {
	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error signing message")
		return nil, err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error signing message")
		return nil, err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pvks, err := getPrivateObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error signing message")
		return nil, err
	}
	if len(pvks) == 0 {
		log.Fatal("Error signing message")
		return nil, errors.New("Object handle not found")
	}

	err = p.SignInit(
		session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
		},
		pvks[0],
	)
	if err != nil {
		log.Println(err)
		log.Fatal("Error signing message")
		return nil, err
	}

	sign, err := p.Sign(session, message)
	if err != nil {
		log.Println(err)
		log.Fatal("Error signing message")
		return nil, err
	}

	return sign, nil
}

func VerifySign(path, keyId, keyName, pin, tokenLabel string, message, signature []byte) error {
	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error verifying message")
		return err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error verifying message")
		return err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pbks, err := getPublicObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error verifying message")
		return err
	}
	if len(pbks) == 0 {
		log.Fatal("Error verifying message")
		return errors.New("Object handle not found")
	}

	err = p.VerifyInit(
		session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
		},
		pbks[0],
	)
	if err != nil {
		log.Println(err)
		log.Fatal("Error verifying message")
		return err
	}

	err = p.Verify(session, message, signature)
	if err != nil {
		log.Println(err)
		log.Fatal("Error verifying message")
		return err
	}

	return nil
}

func EncryptMessage(path, keyId, keyName, pin, tokenLabel string, message []byte, useOaepMechanism bool) ([]byte, error) {
	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error encrypting message")
		return nil, err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error encrypting message")
		return nil, err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pbks, err := getPublicObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error encrypting message")
		return nil, err
	}
	if len(pbks) == 0 {
		log.Fatal("Error encrypting message")
		return nil, errors.New("Object handle not found")
	}

	if useOaepMechanism {
		oaepParams := pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA256,
			pkcs11.CKG_MGF1_SHA256,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte(""),
		)
		err = p.EncryptInit(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)},
			pbks[0],
		)
	} else {
		err = p.EncryptInit(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
			pbks[0],
		)
	}
	if err != nil {
		log.Println(err)
		log.Fatal("Error encrypting message")
		return nil, err
	}

	encryptedData, err := p.Encrypt(session, message)
	if err != nil {
		log.Println(err)
		log.Fatal("Error encrypting message")
		return nil, err
	}

	return encryptedData, nil
}

func DecryptMessage(path, keyId, keyName, pin, tokenLabel string, encryptedMessage []byte, useOaepMechanism bool) ([]byte, error) {
	p, err := Init(path)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decrypting message")
		return nil, err
	}
	defer p.Destroy()
	defer p.Finalize()

	session, err := openSession(p, tokenLabel, pin)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decrypting message")
		return nil, err
	}

	defer p.CloseSession(session)
	defer p.Logout(session)

	pvks, err := getPrivateObjectHandles(p, session, keyId, keyName)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decrypting message")
		return nil, err
	}

	if len(pvks) == 0 {
		log.Fatal("Error decrypting message")
		return nil, errors.New("Object handle not found")
	}

	if useOaepMechanism {
		oaepParams := pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA256,
			pkcs11.CKG_MGF1_SHA256,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte(""),
		)
		err = p.DecryptInit(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)},
			pvks[0],
		)
	} else {
		err = p.DecryptInit(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
			pvks[0],
		)
	}
	if err != nil {
		log.Println(err)
		log.Fatal("Error decrypting message")
		return nil, err
	}

	decryptedData, err := p.Decrypt(session, encryptedMessage)
	if err != nil {
		log.Println(err)
		log.Fatal("Error decrypting message")
		return nil, err
	}

	return decryptedData, nil
}

func getPublicKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, publicKeyObjectHandle pkcs11.ObjectHandle) (string, error) {
	pr, err := p.GetAttributeValue(
		session,
		publicKeyObjectHandle,
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		},
	)
	if err != nil {
		return "", err
	}

	modulus := new(big.Int)
	modulus.SetBytes(pr[0].Value)
	bigExponent := new(big.Int)
	bigExponent.SetBytes(pr[1].Value)
	exponent := int(bigExponent.Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))

	return pubkeyPem, nil
}

func getPublicObjectHandles(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyId, keyName string) ([]pkcs11.ObjectHandle, error) {
	var publicKeyAttributes []*pkcs11.Attribute
	if keyId != "" {
		publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_ID, keyId))
	} else if keyName != "" {
		publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName))
	} else {
		return []pkcs11.ObjectHandle{}, errors.New("keyId or keyName is required field")
	}

	publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
	publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true))
	publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true))
	publicKeyAttributes = append(publicKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))

	err := p.FindObjectsInit(session, publicKeyAttributes)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	objectHandles, _, err := p.FindObjects(session, 1)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	return objectHandles, nil
}

func getPrivateObjectHandles(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyId, keyName string) ([]pkcs11.ObjectHandle, error) {
	var privateKeyAttributes []*pkcs11.Attribute
	if keyId != "" {
		privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_ID, keyId))
	} else if keyName != "" {
		privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName))
	} else {
		return []pkcs11.ObjectHandle{}, errors.New("keyId or keyName is required field")
	}

	privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_SIGN, true))
	privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
	privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true))
	privateKeyAttributes = append(privateKeyAttributes, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))

	err := p.FindObjectsInit(session, privateKeyAttributes)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	objectHandles, _, err := p.FindObjects(session, 1)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		return []pkcs11.ObjectHandle{}, err
	}

	return objectHandles, nil
}

type ErsHsmDecryptor struct {
	pkcs11LibPath string
	slotPin       string
	keyId         string
	keyName       string
	tokenLabel    string
}

func (ersDecryptor ErsHsmDecryptor) Decrypt(ciphertext, label []byte) (plaintext []byte, err error) {
	return DecryptMessage(
		ersDecryptor.pkcs11LibPath,
		ersDecryptor.keyId,
		ersDecryptor.keyName,
		ersDecryptor.slotPin,
		ersDecryptor.tokenLabel,
		ciphertext,
		true,
	)
}

func InitializeErsHsmDecryptor() *ErsHsmDecryptor {
	path := TakeInput("Please enter pkcs11 lib path")
	pin := TakePinInput("Please enter user pin")

	keyId, keyName := "", ""
	switch input := TakeInput("Please select option.\n" + "1. Enter key id\n" + "2. Enter key name"); input {
	case "1":
		keyId = TakeInput("Please enter key id")
	case "2":
		keyName = TakeInput("Please enter key name")
	default:
		log.Fatal("Invalid input")
	}

	tokenLabel := ""
	switch input := TakeInput("Please select option.\n" + "1. Enter token label\n" + "2. Skip"); input {
	case "1":
		tokenLabel = TakeInput("Enter token label")
	case "2":
	default:
		log.Fatal("Invalid input")
	}

	return &ErsHsmDecryptor{
		pkcs11LibPath: path,
		slotPin:       pin,
		keyId:         keyId,
		keyName:       keyName,
		tokenLabel:    tokenLabel,
	}
}

func TakeInput(text string) string {
	var input string

	fmt.Println(text)
	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
		return ""
	}

	return input
}

func TakePinInput(text string) string {
	fmt.Println(text)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
		return ""
	}

	return string(bytepw)
}

func SaveFile(name, content string) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(content)

	return nil
}
