package factotum

import (
	"net"
	"strings"
	"testing"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

func TestRPC_Start(t *testing.T) {
	sessions := NewSessions()
	// Mock keyring for RPC (we need a signing key for Read/done state)
	tempDir := t.TempDir()
	kr, _ := NewKeyring(tempDir)

	rpc := NewRPC(sessions, kr, "")
	fid := uint32(100)

	// 1. Open session
	rpc.Open(fid)
	sess, ok := sessions.Get(fid)
	assert.True(t, ok)
	assert.Equal(t, "start", sess.State)

	// 2. Send Start command
	cmd := "start proto=webauthn role=register user=alice"
	err := rpc.Write(fid, []byte(cmd))
	assert.NoError(t, err)

	// Verify state transition
	sess, _ = sessions.Get(fid)
	assert.Equal(t, "challenged", sess.State)
	assert.Equal(t, "alice", sess.User)
	assert.NotEmpty(t, sess.Challenge)
}

func startMockVFS(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			req, err := p9.ReadFcall(conn)
			if err != nil {
				return
			}

			resp := &p9.Fcall{Tag: req.Tag}
			switch req.Type {
			case p9.Tattach:
				resp.Type = p9.Rattach
				resp.Qid = p9.Qid{Type: p9.QTDIR}
			case p9.Twalk:
				resp.Type = p9.Rwalk
				resp.Wqid = make([]p9.Qid, len(req.Wname))
				for i := range resp.Wqid {
					resp.Wqid[i] = p9.Qid{Type: p9.QTDIR}
				}
			case p9.Tcreate:
				resp.Type = p9.Rcreate
				resp.Qid = p9.Qid{Type: p9.QTFILE}
			case p9.Twrite:
				resp.Type = p9.Rwrite
				resp.Count = req.Count
			case p9.Tclunk:
				resp.Type = p9.Rclunk
			default:
				resp.Type = p9.Rerror
				resp.Ename = "not implemented in mock"
			}
			b, _ := resp.Bytes()
			conn.Write(b)
		}
	}()

	return ln.Addr().String()
}

func TestRPC_Write_And_Read_Flow(t *testing.T) {
	sessions := NewSessions()
	tempDir := t.TempDir()
	kr, _ := NewKeyring(tempDir)

	vfsAddr := startMockVFS(t)
	rpc := NewRPC(sessions, kr, vfsAddr)
	fid := uint32(200)

	// Initialize to challenged state
	rpc.Open(fid)
	rpc.Write(fid, []byte("start proto=webauthn role=register user=bob"))

	// 1. Read Challenge
	resp, err := rpc.Read(fid)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(resp, "challenge "), "Response should start with 'challenge'")

	// 2. Write Attestation (dummy for v1)
	err = rpc.Write(fid, []byte("write some-base64-attestation"))
	assert.NoError(t, err)

	// Verify state is done
	sess, _ := sessions.Get(fid)
	assert.Equal(t, "done", sess.State)

	// 3. Read Ticket
	resp, err = rpc.Read(fid)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(resp, "ok ticket=/priv/sessions/bob/"), "Response should contain ticket path")
}

func TestRPC_InvalidFlows(t *testing.T) {
	sessions := NewSessions()
	rpc := NewRPC(sessions, nil, "")
	fid := uint32(999)

	// Write to non-existent session
	err := rpc.Write(fid, []byte("start ..."))
	assert.Error(t, err)

	// Open session
	rpc.Open(fid)

	// Invalid Start command (missing user)
	err = rpc.Write(fid, []byte("start proto=webauthn role=register"))
	assert.Error(t, err)

	// Invalid Protocol
	err = rpc.Write(fid, []byte("start proto=ssh role=auth user=alice"))
	assert.Error(t, err)
}
