package factotum

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRotateSigningKey(t *testing.T) {
	tempDir := t.TempDir()
	kr, err := NewKeyring(tempDir)
	assert.NoError(t, err)

	// consistent initial state
	oldPub := kr.PublicKey()
	oldPriv := kr.SigningKey()

	// Initial key file content
	keyPath := filepath.Join(tempDir, "signing.key")
	initialContent, err := os.ReadFile(keyPath)
	assert.NoError(t, err)

	// Wait a bit to ensure timestamp difference (though file system might be granulr)
	time.Sleep(10 * time.Millisecond)

	// Rotate
	err = kr.RotateSigningKey()
	assert.NoError(t, err)

	// Verify new key is different
	newPub := kr.PublicKey()
	newPriv := kr.SigningKey()
	assert.NotEqual(t, oldPub, newPub)
	assert.NotEqual(t, oldPriv, newPriv)

	// Verify new key file content
	newContent, err := os.ReadFile(keyPath)
	assert.NoError(t, err)
	assert.NotEqual(t, initialContent, newContent)

	// Verify new content is valid base64 key
	decoded, _ := base64.StdEncoding.DecodeString(string(newContent))
	assert.Equal(t, ed25519.PrivateKeySize, len(decoded))
	assert.Equal(t, []byte(newPriv), decoded)

	// Verify old key is archived
	files, err := os.ReadDir(tempDir)
	assert.NoError(t, err)

	archivedFound := false
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "signing.key.") {
			archivedFound = true
			content, _ := os.ReadFile(filepath.Join(tempDir, f.Name()))
			assert.Equal(t, initialContent, content)
		}
	}
	assert.True(t, archivedFound, "Archived key file not found")
}
