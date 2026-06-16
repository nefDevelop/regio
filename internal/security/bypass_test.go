package security

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"

	"regio/internal/db"
	"regio/internal/models"
	_ "modernc.org/sqlite"
)

func setupBypassDB(t *testing.T) {
	t.Helper()
	os.MkdirAll("./testdata", 0755)
	t.Cleanup(func() { os.RemoveAll("./testdata") })
	db.InitDB()
	// Reset state
	bpMu.Lock()
	BypassKeys = make(map[string]models.BypassKey)
	bpMu.Unlock()
	db.DB.Exec("DELETE FROM bypass_keys")
}

func TestBypassHash(t *testing.T) {
	token := "my-bypass-token-123"
	hash1 := bypassHash(token)
	hash2 := bypassHash(token)
	if hash1 != hash2 {
		t.Error("bypassHash is not deterministic")
	}
	if hash1 == "" {
		t.Error("bypassHash returned empty")
	}
	// Verify it's a valid SHA-256 hash (44 chars in base64 RawURL)
	if len(hash1) != 43 && len(hash1) != 44 {
		t.Errorf("bypassHash length = %d, want ~43-44", len(hash1))
	}
	_, err := base64.RawURLEncoding.DecodeString(hash1)
	if err != nil {
		t.Errorf("bypassHash = %q, not valid base64url: %v", hash1, err)
	}

	// Verify it's the same as SHA-256
	expected := sha256.Sum256([]byte(token))
	expectedStr := base64.RawURLEncoding.EncodeToString(expected[:])
	if hash1 != expectedStr {
		t.Errorf("bypassHash = %q, want %q", hash1, expectedStr)
	}
}

func TestAddCheckBypass(t *testing.T) {
	setupBypassDB(t)

	token := "test-bypass-token"
	name := "Test Service"
	host := "app.example.com"

	AddBypassKey(token, name, host)

	// Verify check works
	ok, gotName := CheckBypass(token, host)
	if !ok {
		t.Error("CheckBypass returned false, want true")
	}
	if gotName != name {
		t.Errorf("CheckBypass returned name %q, want %q", gotName, name)
	}

	// Wrong host
	ok, _ = CheckBypass(token, "wrong-host.com")
	if ok {
		t.Error("CheckBypass with wrong host should return false")
	}

	// Invalid token
	ok, _ = CheckBypass("invalid-token", host)
	if ok {
		t.Error("CheckBypass with invalid token should return false")
	}

	// Empty token
	ok, _ = CheckBypass("", host)
	if ok {
		t.Error("CheckBypass with empty token should return false")
	}
}

func TestAddDeleteBypass(t *testing.T) {
	setupBypassDB(t)

	token := "delete-test-token"
	name := "To Delete"
	host := "delete-test.com"

	AddBypassKey(token, name, host)

	// Verify it exists via GetBypassKeys
	keys := GetBypassKeys()
	found := false
	for _, k := range keys {
		if k.Name == name && k.Host == host {
			found = true
			break
		}
	}
	if !found {
		t.Error("Bypass key not found in GetBypassKeys after Add")
	}

	// Delete - need to use the hash
	tokenHash := bypassHash(token)
	DeleteBypassKey(tokenHash)

	// Verify it's gone
	ok, _ := CheckBypass(token, host)
	if ok {
		t.Error("CheckBypass should return false after Delete")
	}
}

func TestBypassMultipleKeys(t *testing.T) {
	setupBypassDB(t)

	keys := []struct {
		token string
		name  string
		host  string
	}{
		{"token-a", "Service A", "a.example.com"},
		{"token-b", "Service B", "b.example.com"},
		{"token-c", "Service C", "a.example.com"},
	}

	for _, k := range keys {
		AddBypassKey(k.token, k.name, k.host)
	}

	// Verify all are accessible
	for _, k := range keys {
		ok, name := CheckBypass(k.token, k.host)
		if !ok {
			t.Errorf("Key %q should be valid for %s", k.token, k.host)
		}
		if name != k.name {
			t.Errorf("Key %q: got name %q, want %q", k.token, name, k.name)
		}
	}

	// Verify count
	allKeys := GetBypassKeys()
	if len(allKeys) != 3 {
		t.Errorf("GetBypassKeys returned %d keys, want 3", len(allKeys))
	}
}

func TestBypassTokenNotStoredInPlaintext(t *testing.T) {
	setupBypassDB(t)

	rawToken := "sensitive-bypass-token"
	AddBypassKey(rawToken, "test", "example.com")

	// The token column should contain the hash, not the raw token
	var storedToken string
	err := db.DB.QueryRow("SELECT token FROM bypass_keys WHERE host = 'example.com'").Scan(&storedToken)
	if err != nil {
		t.Fatalf("Error querying bypass_keys: %v", err)
	}

	if storedToken == rawToken {
		t.Error("Token stored in plaintext! Expected hash.")
	}
	if storedToken != bypassHash(rawToken) {
		t.Errorf("Stored token %q does not match expected hash %q", storedToken, bypassHash(rawToken))
	}
}
