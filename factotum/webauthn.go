// webauthn.go provides FIDO2/WebAuthn verification logic.
// It wraps the go-webauthn library for registration and authentication.
package factotum

// WebAuthn configuration and helpers will be implemented here.
// For v1, we stub this out. The RPC handler has placeholder logic.
//
// Required methods:
// - BeginRegistration(user) -> challenge, sessionData
// - FinishRegistration(sessionData, attestation) -> credential
// - BeginLogin(user) -> challenge, sessionData
// - FinishLogin(sessionData, assertion) -> success

// This file will be expanded when we integrate the go-webauthn library.
