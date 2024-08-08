package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"time"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/sync/errgroup"
)

func Reset() {
	nodeUrl := []string{"http://localhost:8000", "http://localhost:8001"}

	// creds := make([]tsm.PasswordCredentials, 0, 2)

	for i, url := range nodeUrl {
		createUsers(url, i)
		// cred := resetUserPassword(url, i)
		// creds = append(creds, cred)
	}

	// keyID := keygen(creds)
	// sign(creds, keyID)
}

func createUsers(nodeUrl string, index int) {
	servers := []string{nodeUrl}
	var nodes []tsm.Node
	for _, s := range servers {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		nodes = append(nodes, tsm.NewURLNode(*u, tsm.NullAuthenticator{}))
	}
	client := tsm.NewClient(nodes)
	ac := tsm.NewAdminClient(client)

	version, err := ac.TSMVersion()
	if err != nil {
		fmt.Println("Could not ping. Retrying...")
		time.Sleep(time.Second)
		version, err = ac.TSMVersion()
	}
	if err != nil {
		fmt.Println("Could not ping servers")
		panic(err)
	}
	fmt.Printf("TSM version: %s\n", version.Version)

	fmt.Println("Creating initial admin")
	uc := tsm.NewUsersClient(client)
	adminCreds, err := uc.CreateInitialAdmin()
	if err != nil {
		fmt.Printf("Could not create initial admin: %s\n", err)
		fmt.Println("Exiting. We expect the TSM has already been initialized.")
		return
	}
	adminJson, err := adminCreds.Encode()
	if err != nil {
		panic(err)
	}
	
	err = os.WriteFile(fmt.Sprintf("admin%d.json", index), []byte(adminJson), 0666)
	if err != nil {
		panic(err)
	}

	admClient, err := tsm.NewPasswordClientFromCredentials(adminCreds)
	if err != nil {
		panic(err)
	}

	fmt.Println("Creating key user")
	usersClient := tsm.NewUsersClient(admClient)

	userCreds, err := usersClient.CreatePasswordUser(fmt.Sprintf("user%d", index), "")
	if err != nil {
		panic(err)
	}
	fmt.Println("Created regular user with user ID", userCreds.UserID)
	userJson, err := userCreds.Encode()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(fmt.Sprintf("user%d.json", index), []byte(userJson), 0666)
	if err != nil {
		panic(err)
	}
}

func resetUserPassword(nodeUrl string, index int) tsm.PasswordCredentials {
	servers := []string{nodeUrl}
	var nodes []tsm.Node
	for _, s := range servers {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		nodes = append(nodes, tsm.NewURLNode(*u, tsm.NullAuthenticator{}))
	}
	client := tsm.NewClient(nodes)
	ac := tsm.NewAdminClient(client)

	version, err := ac.TSMVersion()
	if err != nil {
		fmt.Println("Could not ping. Retrying...")
		time.Sleep(time.Second)
		version, err = ac.TSMVersion()
	}
	if err != nil {
		fmt.Println("Could not ping servers")
		panic(err)
	}
	fmt.Printf("TSM version: %s\n", version.Version)

	adminBytes, err := os.ReadFile(fmt.Sprintf("admin%d.json", index))
	if err != nil {
		panic(err)
	}
	var adminCreds tsm.PasswordCredentials
	if err := adminCreds.UnmarshalJSON(adminBytes); err != nil {
		panic(err)
	}

	admClient, err := tsm.NewPasswordClientFromCredentials(adminCreds)
	if err != nil {
		panic(err)
	}

	usersClient := tsm.NewUsersClient(admClient)

	userBytes, err := os.ReadFile(fmt.Sprintf("user%d.json", index))
	if err != nil {
		panic(err)
	}
	var userCreds tsm.PasswordCredentials
	if err := userCreds.UnmarshalJSON(userBytes); err != nil {
		panic(err)
	}

	fmt.Println("Resetting passwords for user", userCreds.UserID)
	fmt.Println("Old passwords", userCreds.Passwords)
	newCreds, err := usersClient.ResetPassword(userCreds.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Println("New creds", newCreds)

	userNewJson, err := newCreds.Encode()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(fmt.Sprintf("user%d.json", index), []byte(userNewJson), 0666)
	if err != nil {
		panic(err)
	}

	return newCreds
}

func keygen(creds []tsm.PasswordCredentials) string {
	ecdsaClients := make([]tsm.ECDSAClient, 2)
	for player := 0; player < 2; player++ {
		credsPlayer := tsm.PasswordCredentials{
			UserID:    creds[player].UserID,
			URLs:      []string{creds[player].URLs[0]},
			Passwords: []string{creds[player].Passwords[0]},
		}
		client, err := tsm.NewPasswordClientFromCredentials(credsPlayer)
		if err != nil {
			panic(err)
		}
		ecdsaClients[player] = tsm.NewECDSAClient(client)
	}

	// Generate ECSDA key

	keyGenSessionID := tsm.GenerateSessionID()
	var keyID string
	var eg errgroup.Group
	for i := 0; i < 2; i++ {
		i := i
		eg.Go(func() error {
			var err error
			keyID, err = ecdsaClients[i].KeygenWithSessionID(keyGenSessionID, "secp256k1")
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		panic(err)
	}
	fmt.Println("Generated key with ID:", keyID)

	return keyID
}

func sign(creds []tsm.PasswordCredentials, keyID string) {
	ecdsaClients := make([]tsm.ECDSAClient, 2)
	for player := 0; player < 2; player++ {
		credsPlayer := tsm.PasswordCredentials{
			UserID:    creds[player].UserID,
			URLs:      []string{creds[player].URLs[0]},
			Passwords: []string{creds[player].Passwords[0]},
		}
		client, err := tsm.NewPasswordClientFromCredentials(credsPlayer)
		if err != nil {
			panic(err)
		}
		ecdsaClients[player] = tsm.NewECDSAClient(client)
	}

	message := []byte("This is the message to be signed")
	msgHash := sha256.Sum256(message)
	chainPath := []uint32{2, 5} // Sign using the derived key m/2/5

	players := []int{0, 1} // Choose a subset of threshold+1 players to participate in signature generation
	partialSignatures := make([][]byte, len(players))

	// The call to PartialSign is blocking, so we must call each ecdsaClient concurrently.
	signSessionID := ecdsaClients[0].GenerateSessionID()

	var eg errgroup.Group
	for i, player := range players {
		i, player := i, player
		eg.Go(func() error {
			var err error
			partialSignatures[i], err = ecdsaClients[player].PartialSign(signSessionID, keyID, chainPath, msgHash[:], players...)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		panic(err)
	}

	// Combine the partial signatures into an actual signature

	signature, _, err := tsm.ECDSAFinalize(partialSignatures...)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(signature))
}
