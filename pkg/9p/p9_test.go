package p9

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode_Tversion(t *testing.T) {
	req := &Fcall{
		Type:    Tversion,
		Tag:     NOTAG,
		Msize:   8192,
		Version: "9P2000",
	}

	b, err := req.Bytes()
	assert.NoError(t, err)

	decoded, err := Unmarshal(b[4:], binary.LittleEndian.Uint32(b[0:4]))
	assert.NoError(t, err)

	assert.Equal(t, req.Type, decoded.Type)
	assert.Equal(t, req.Msize, decoded.Msize)
	assert.Equal(t, req.Version, decoded.Version)
}

func TestEncodeDecode_Rread(t *testing.T) {
	req := &Fcall{
		Type: Rread,
		Tag:  1,
		Data: []byte("hello world"),
	}

	b, err := req.Bytes()
	assert.NoError(t, err)

	decoded, err := Unmarshal(b[4:], binary.LittleEndian.Uint32(b[0:4]))
	assert.NoError(t, err)

	assert.Equal(t, req.Data, decoded.Data)
}

func TestDir_Marshal(t *testing.T) {
	d := Dir{
		Type:   0,
		Dev:    0,
		Qid:    Qid{Type: QTFILE, Vers: 1, Path: 123},
		Mode:   0644,
		Atime:  1000,
		Mtime:  2000,
		Length: 1024,
		Name:   "foo.txt",
		Uid:    "alice",
		Gid:    "users",
		Muid:   "alice",
	}

	b := d.Bytes()

	d2, n, err := UnmarshalDir(b)
	assert.NoError(t, err)
	assert.Equal(t, len(b), n)

	assert.Equal(t, d.Name, d2.Name)
	assert.Equal(t, d.Length, d2.Length)
	assert.Equal(t, d.Uid, d2.Uid)
	assert.Equal(t, d.Qid, d2.Qid)
}
