package factotum

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCtl_Key(t *testing.T) {
	tempDir := t.TempDir()
	kr, _ := NewKeyring(tempDir)
	ctl := NewCtl(kr)

	user := "dave"

	// 1. Add WebAuthn Key
	// "key proto=webauthn user=<userid> cose=<base64-cose-key>"
	dummyCose := []byte("dummy-cose-key-content")
	coseB64 := base64.StdEncoding.EncodeToString(dummyCose)
	cmd := fmt.Sprintf("key proto=webauthn user=%s cose=%s", user, coseB64)

	resp, err := ctl.Write([]byte(cmd))
	assert.NoError(t, err)
	assert.Equal(t, "ok", resp)

	// Verify in keyring
	saved, err := kr.LoadUserKey(user)
	assert.NoError(t, err)
	assert.Equal(t, dummyCose, saved)
}

func TestCtl_SSH_Key(t *testing.T) {
	tempDir := t.TempDir()
	kr, _ := NewKeyring(tempDir)
	ctl := NewCtl(kr)

	user := "eve"
	sshKey := "ssh-ed25519 AAAAC3Nza..."

	// "key proto=ssh user=<userid> <ssh-pubkey-text>"
	cmd := fmt.Sprintf("key proto=ssh user=%s %s", user, sshKey)

	resp, err := ctl.Write([]byte(cmd))
	assert.NoError(t, err)
	assert.Equal(t, "ok", resp)

	// Verify
	saved, err := kr.LoadUserKey(user)
	assert.NoError(t, err)
	assert.Equal(t, []byte(sshKey), saved)
}

func TestCtl_DelKey(t *testing.T) {
	tempDir := t.TempDir()
	kr, _ := NewKeyring(tempDir)
	ctl := NewCtl(kr)

	user := "frank"
	// Setup: create a key manually
	kr.SaveUserKey(user, []byte("key-to-delete"))

	// Delete via CTL
	cmd := fmt.Sprintf("delkey user=%s", user)
	resp, err := ctl.Write([]byte(cmd))
	assert.NoError(t, err)
	assert.Equal(t, "ok", resp)

	// Verify gone
	_, err = kr.LoadUserKey(user)
	assert.Error(t, err)
}
