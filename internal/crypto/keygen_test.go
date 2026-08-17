package crypto

import "testing"

func TestKeyGenEncryptDecrypt(t *testing.T) {
	k, errGen := GenerateKey()
	if errGen != nil {
		t.Fatal(errGen)
	}
	if len(k) < 48 {
		t.Fatalf("key too short: %d", len(k))
	}
	if k[:3] != "sk-" {
		t.Fatalf("bad prefix: %q", k[:3])
	}
	h := HashKey(k)
	if len(h) != 64 {
		t.Fatalf("bad hash len: %d", len(h))
	}
	secret := []byte("12345678901234567890123456789012")
	c, n, errEnc := EncryptKey(k, secret)
	if errEnc != nil {
		t.Fatal(errEnc)
	}
	if len(n) != 12 {
		t.Fatalf("bad nonce: %d", len(n))
	}
	plain, errDec := DecryptKey(c, n, secret)
	if errDec != nil {
		t.Fatal(errDec)
	}
	if plain != k {
		t.Fatalf("decrypt mismatch")
	}
}
