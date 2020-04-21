package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	err := Main(context.Background())
	if err != nil {
		panic(err)
	}
}

func Main(ctx context.Context) error {
	flag.Parse()
	switch flag.Arg(0) {
	case "gen":
		return Gen(ctx)
	case "import":
		return Import(ctx)
	default:
		fmt.Printf("%s <gen|import>\n", os.Args[0])
		os.Exit(1)
		return nil
	}
}

func Gen(ctx context.Context) error {
	rawKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	return Output(ctx, rawKey)
}

func Output(ctx context.Context, rawKey *ecdsa.PrivateKey) error {
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

func Import(ctx context.Context) error {
	fmt.Print("Enter private key: ")
	hexKey, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	keyBytes, err := hex.DecodeString(string(hexKey))
	if err != nil {
		return err
	}
	rawKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return err
	}
	return Output(ctx, rawKey)
}
