// ctl.go handles the /ctl file interface.
// It provides key management: adding and removing public keys.
package factotum

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Ctl handles the /ctl file operations.
type Ctl struct {
	keyring *Keyring
}

// NewCtl creates a new Ctl handler.
func NewCtl(keyring *Keyring) *Ctl {
	return &Ctl{keyring: keyring}
}

// Write processes a key management command.
// Commands:
//
//	key proto=webauthn user=<userid> cose=<base64-cose-key>
//	key proto=ssh user=<userid> <ssh-pubkey-text>
//	delkey user=<userid>
func (c *Ctl) Write(data []byte) (string, error) {
	cmd := strings.TrimSpace(string(data))
	parts := strings.Fields(cmd)

	if len(parts) == 0 {
		return "", errors.New("empty command")
	}

	switch parts[0] {
	case "key":
		return c.handleKey(parts[1:])
	case "delkey":
		return c.handleDelKey(parts[1:])
	default:
		return "", errors.New("unknown command: " + parts[0])
	}
}

// handleKey processes the "key" command.
func (c *Ctl) handleKey(parts []string) (string, error) {
	params := parseCtlParams(parts)

	user := params["user"]
	if user == "" {
		return "", errors.New("user required")
	}

	proto := params["proto"]

	switch proto {
	case "webauthn":
		coseB64 := params["cose"]
		if coseB64 == "" {
			return "", errors.New("cose key required for webauthn")
		}
		coseKey, err := base64.StdEncoding.DecodeString(coseB64)
		if err != nil {
			return "", errors.New("invalid base64 cose key")
		}
		if err := c.keyring.SaveUserKey(user, coseKey); err != nil {
			return "", err
		}
		return "ok", nil

	case "ssh":
		// SSH keys are stored as-is (text)
		// Find the key after proto= and user=
		keyStart := strings.Index(string(parts[len(parts)-1]), " ")
		if keyStart == -1 {
			return "", errors.New("ssh key required")
		}
		sshKey := parts[len(parts)-1]
		if err := c.keyring.SaveUserKey(user, []byte(sshKey)); err != nil {
			return "", err
		}
		return "ok", nil

	default:
		return "", errors.New("unsupported protocol: " + proto)
	}
}

// handleDelKey processes the "delkey" command.
func (c *Ctl) handleDelKey(parts []string) (string, error) {
	params := parseCtlParams(parts)

	user := params["user"]
	if user == "" {
		return "", errors.New("user required")
	}

	if err := c.keyring.DeleteUserKey(user); err != nil {
		return "", err
	}

	return "ok", nil
}

// parseCtlParams converts ["key=value", ...] to map[string]string.
func parseCtlParams(parts []string) map[string]string {
	m := make(map[string]string)
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}
