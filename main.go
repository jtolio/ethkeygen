package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	err := Main(context.Background())
	if err != nil {
		panic(err)
	}
}

func Main(ctx context.Context) error {
	rawKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	key := hex.EncodeToString(crypto.FromECDSA(rawKey))
	address := crypto.PubkeyToAddress(rawKey.PublicKey).Hex()
	fmt.Printf("Key: %s\nAddress: %s\n", key, address)
	ks := keystore.NewKeyStore(".", keystore.StandardScryptN, keystore.StandardScryptP)
	fmt.Print("Enter Keystore Passphrase: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Printf("\nPassphrase typed: %q\n", string(bytePassword))
	a, err := ks.ImportECDSA(rawKey, string(bytePassword))
	if err != nil {
		return err
	}
	fmt.Printf("Keystore Address: %s\n", a.Address.Hex())
	return nil
}
