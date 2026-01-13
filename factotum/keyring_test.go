package factotum

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigningKeyGeneration(t *testing.T) {
	// Use a temporary directory for the keyring
	tempDir := t.TempDir()

	// 1. Initialize Keyring (should generate new key)
	kr, err := NewKeyring(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, kr)
	assert.NotEmpty(t, kr.SigningKey())

	// Verify key file exists
	keyPath := filepath.Join(tempDir, "signing.key")
	_, err = os.Stat(keyPath)
	assert.NoError(t, err)

	// 2. Re-initialize (should load existing key)
	kr2, err := NewKeyring(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, kr.SigningKey(), kr2.SigningKey())
}

func TestUserKeyManagement(t *testing.T) {
	tempDir := t.TempDir()
	kr, err := NewKeyring(tempDir)
	assert.NoError(t, err)

	user := "alice"
	fakeKey := []byte("fake-public-key")

	// 1. Save Key
	err = kr.SaveUserKey(user, fakeKey)
	assert.NoError(t, err)

	// Verify file on disk
	keyPath := filepath.Join(tempDir, user, "pubkey")
	content, err := os.ReadFile(keyPath)
	assert.NoError(t, err)
	assert.Equal(t, fakeKey, content)

	// 2. Load Key
	loaded, err := kr.LoadUserKey(user)
	assert.NoError(t, err)
	assert.Equal(t, fakeKey, loaded)

	// 3. Delete Key
	err = kr.DeleteUserKey(user)
	assert.NoError(t, err)

	// Verify deletion
	_, err = os.Stat(keyPath)
	assert.True(t, os.IsNotExist(err))
}
