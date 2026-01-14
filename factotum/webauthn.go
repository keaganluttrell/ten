package factotum

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnConfig holds WebAuthn configuration.
type WebAuthnConfig struct {
	RPDisplayName string // "Ten Operating System"
	RPID          string // "localhost" or actual domain
	RPOrigin      string // "http://localhost:9009"
}

// WebAuthnHandler wraps the go-webauthn library.
type WebAuthnHandler struct {
	webAuthn *webauthn.WebAuthn
	store    *CredentialStore
}

// NewWebAuthnHandler creates a new WebAuthn handler.
func NewWebAuthnHandler(cfg WebAuthnConfig, store *CredentialStore) (*WebAuthnHandler, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, err
	}

	return &WebAuthnHandler{
		webAuthn: webAuthn,
		store:    store,
	}, nil
}

// BeginRegistration starts the registration ceremony.
func (w *WebAuthnHandler) BeginRegistration(username string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	// Try to load existing user
	user, err := w.store.LoadUser(username)
	if err != nil {
		// Create new user
		user = &User{
			ID:          []byte(username),
			Name:        username,
			DisplayName: username,
			Credentials: []webauthn.Credential{},
		}
	}

	options, sessionData, err := w.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}

	return options, sessionData, nil
}

// FinishRegistration completes the registration ceremony.
func (w *WebAuthnHandler) FinishRegistration(username string, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	user, err := w.store.LoadUser(username)
	if err != nil {
		// Create new user
		user = &User{
			ID:          []byte(username),
			Name:        username,
			DisplayName: username,
			Credentials: []webauthn.Credential{},
		}
	}

	credential, err := w.webAuthn.CreateCredential(user, *sessionData, response)
	if err != nil {
		return nil, err
	}

	// Save credential
	if err := w.store.AddCredential(username, *credential); err != nil {
		return nil, err
	}

	return credential, nil
}

// BeginLogin starts the login ceremony.
func (w *WebAuthnHandler) BeginLogin(username string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	user, err := w.store.LoadUser(username)
	if err != nil {
		return nil, nil, err
	}

	options, sessionData, err := w.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}

	return options, sessionData, nil
}

// FinishLogin completes the login ceremony.
func (w *WebAuthnHandler) FinishLogin(username string, sessionData *webauthn.SessionData, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	user, err := w.store.LoadUser(username)
	if err != nil {
		return nil, err
	}

	credential, err := w.webAuthn.ValidateLogin(user, *sessionData, response)
	if err != nil {
		return nil, err
	}

	return credential, nil
}
