package factotum

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestProtocolStructure(t *testing.T) {
	// Test to see what fields CredentialCreationResponse has
	_ = protocol.CredentialCreationResponse{}

	// Test to see what fields CredentialAssertionResponse has
	_ = protocol.CredentialAssertionResponse{}

	t.Log("Struct test complete")
}
