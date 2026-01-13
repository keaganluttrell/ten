package kernel

import (
	"fmt"
	"log"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// HostAuthHandshake performs the Tauth -> Tread(nonce) -> Twrite(sig) ceremony.
// Returns the authenticated afid, or NOFID if auth failed/not attempted.
func HostAuthHandshake(client *Client, host *HostIdentity) (uint32, error) {
	if host == nil {
		return p9.NOFID, nil
	}

	afid := uint32(100) // Reserved range for internal auth?

	// Helper to reduce boilerplate
	rpcCheck := func(req *p9.Fcall) (*p9.Fcall, error) {
		resp, err := client.RPC(req)
		if err != nil {
			return nil, err
		}
		if resp.Type == p9.Rerror {
			return nil, fmt.Errorf("9p_error: %s", resp.Ename)
		}
		return resp, nil
	}

	// 1. Tauth
	_, err := rpcCheck(&p9.Fcall{Type: p9.Tauth, Afid: afid, Uname: "kernel", Aname: "/"})
	if err != nil {
		// Log warning but allow proceeding (maybe VFS has auth disabled?)
		// But if auth is required later, it will fail then.
		log.Printf("Boot Warning: Tauth failed: %v", err)
		return p9.NOFID, nil // Or pass error?
	}

	// 2. Read Nonce (32 bytes)
	rResp, err := rpcCheck(&p9.Fcall{Type: p9.Tread, Fid: afid, Offset: 0, Count: 32})
	if err != nil {
		return p9.NOFID, fmt.Errorf("auth_read_nonce_failed: %w", err)
	}
	nonce := rResp.Data

	// 3. Sign Nonce
	sig := host.Sign(nonce)

	// 4. Write Signature
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Twrite, Fid: afid, Data: sig, Count: uint32(len(sig))}); err != nil {
		return p9.NOFID, fmt.Errorf("auth_write_sig_failed: %w", err)
	}

	log.Printf("Boot: Host Auth Successful")
	return afid, nil
}
