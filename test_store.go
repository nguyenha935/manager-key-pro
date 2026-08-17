package main
import (
	"fmt"
	"github.com/nguyenha935/manager-key-pro/internal/store"
	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"encoding/hex"
	"os"
)
func main() {
	os.Remove("/tmp/mkp-test.db")
	db, err := store.Open("/tmp/mkp-test.db")
	if err != nil { panic(err) }
	defer db.Close()
	fmt.Println("✓ db opened")
	
	u, err := db.Users().Create("testuser", "hash123", "", "user")
	if err != nil { panic(err) }
	fmt.Printf("✓ user created: %s (%s)\n", u.Username, u.ID)
	
	plainKey, _ := crypto.GenerateKey()
	fmt.Printf("✓ key generated: %s\n", crypto.Prefix(plainKey))
	
	secret, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	cipher, nonce, _ := crypto.EncryptKey(plainKey, secret)
	
	k, err := db.Keys().Create(store.CreateKeyInput{
		UserID: u.ID,
		KeyHash: crypto.HashKey(plainKey),
		KeyCipher: cipher,
		KeyNonce: nonce,
		Prefix: crypto.Prefix(plainKey),
		Name: "Test Key",
		QuotaKind: "credit",
		QuotaScope: "lifetime",
		QuotaAmount: 1000000,
		ExpiresAt: -1,
		RPM: 60,
	})
	if err != nil { panic(err) }
	fmt.Printf("✓ key created: %s\n", k.ID)
	
	k2, err := db.Keys().ByHash(crypto.HashKey(plainKey))
	if err != nil { panic(err) }
	fmt.Printf("✓ key lookup: %s (quota: %d/%d)\n", k2.Name, k2.QuotaUsed, k2.QuotaAmount)
	
	decrypted, err := crypto.DecryptKey(k2.KeyCipher, k2.KeyNonce, secret)
	if err != nil { panic(err) }
	if decrypted != plainKey { panic("decrypt mismatch") }
	fmt.Println("✓ key decrypted and matches")
	
	fmt.Println("\nAll tests passed.")
}
