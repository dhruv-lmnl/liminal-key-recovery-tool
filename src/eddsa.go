package main

import (
	"crypto/rsa"
	"log"

	"gitlab.com/sepior/ers-lib/ers"
)

func recoverEDDSAPrivateKey(key *rsa.PrivateKey, recoveryInfo []byte, chainpath []uint32) (string, []byte, []byte) {
	ersDecryptor := ers.NewRSADecryptor(key)

	ellipticCurve, privateKeyASN1, masterChainCode, err := ers.RecoverPrivateKey(ersDecryptor, []byte(""), recoveryInfo, chainpath)
	if err != nil {
		log.Println("Error recovering eddsa private key")
		log.Fatal(err)
	}
	return ellipticCurve, privateKeyASN1, masterChainCode
}
