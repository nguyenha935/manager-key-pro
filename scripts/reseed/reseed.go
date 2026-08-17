package main

import (
	"encoding/hex"
	"fmt"
	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

func main() {
	db, err := store.Open("/root/cliproxyapi/mkp.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	k, errK := db.Keys().ByID("key_d4wa6vesn3owtggh")
	if errK != nil {
		fmt.Println("KEY_MISSING")
		return
	}
	secret, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	plain, errD := crypto.DecryptKey(k.KeyCipher, k.KeyNonce, secret)
	if errD != nil {
		panic(errD)
	}
	fmt.Println("KEY:", plain)
	fmt.Println("ID:", k.ID)
	fmt.Println("QUOTA:", k.QuotaUsed, "/", k.QuotaAmount)
}
