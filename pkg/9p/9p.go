// Package p9 implements the 9P2000 protocol encoding and decoding.
// All protocol logic is consolidated here following Locality of Behavior.
package p9

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// --- Constants ---

const (
	OREAD   = 0x00
	OWRITE  = 0x01
	ORDWR   = 0x02
	OEXEC   = 0x03
	OTRUNC  = 0x10
	ORCLOSE = 0x40
)

// --- Message Types ---

const (
	Tversion = 100 + iota
	Rversion
	Tauth
	Rauth
	Tattach
	Rattach
	Terror // 106
	Rerror
	Tflush
	Rflush
	Twalk
	Rwalk
	Topen
	Ropen
	Tcreate
	Rcreate
	Tread
	Rread
	Twrite
	Rwrite
	Tclunk
	Rclunk
	Tremove
	Rremove
	Tstat
	Rstat
	Twstat
	Rwstat
)

// --- Permissions (Mode bits) ---

const (
	DMDIR    = 0x80000000
	DMAPPEND = 0x40000000
	DMEXCL   = 0x20000000
	DMMOUNT  = 0x10000000
	DMAUTH   = 0x08000000
	DMTMP    = 0x04000000
)

// --- Qid Type Constants ---

const (
	QTDIR    = 0x80
	QTAPPEND = 0x40
	QTEXCL   = 0x20
	QTMOUNT  = 0x10
	QTAUTH   = 0x08
	QTTMP    = 0x04
	QTFILE   = 0x00
)

// --- Special Values ---

const (
	NOTAG uint16 = 0xFFFF
	NOFID uint32 = 0xFFFFFFFF
)

// --- Qid ---

// Qid represents a unique file ID on the server.
type Qid struct {
	Type uint8
	Vers uint32
	Path uint64
}

// --- Dir (Stat) ---

// Dir describes a file (directory entry).
// Corresponds to the Plan 9 stat structure.
type Dir struct {
	Type   uint16
	Dev    uint32
	Qid    Qid
	Mode   uint32
	Atime  uint32
	Mtime  uint32
	Length uint64
	Name   string
	Uid    string
	Gid    string
	Muid   string
}

// Bytes encodes a Dir into the wire format: size[2] + contents.
func (d *Dir) Bytes() []byte {
	size := 39 +
		(2 + len(d.Name)) +
		(2 + len(d.Uid)) +
		(2 + len(d.Gid)) +
		(2 + len(d.Muid))

	b := make([]byte, 2+size)
	binary.LittleEndian.PutUint16(b[0:2], uint16(size))

	// Contents
	binary.LittleEndian.PutUint16(b[2:4], d.Type)
	binary.LittleEndian.PutUint32(b[4:8], d.Dev)

	// Qid
	b[8] = d.Qid.Type
	binary.LittleEndian.PutUint32(b[9:13], d.Qid.Vers)
	binary.LittleEndian.PutUint64(b[13:21], d.Qid.Path)

	binary.LittleEndian.PutUint32(b[21:25], d.Mode)
	binary.LittleEndian.PutUint32(b[25:29], d.Atime)
	binary.LittleEndian.PutUint32(b[29:33], d.Mtime)
	binary.LittleEndian.PutUint64(b[33:41], d.Length)

	off := 41
	off += pStrBuf(b[off:], d.Name)
	off += pStrBuf(b[off:], d.Uid)
	off += pStrBuf(b[off:], d.Gid)
	off += pStrBuf(b[off:], d.Muid)

	return b
}

// UnmarshalDir decodes a single Dir from the buffer.
func UnmarshalDir(b []byte) (Dir, int, error) {
	if len(b) < 2 {
		return Dir{}, 0, fmt.Errorf("buffer too short")
	}

	size := int(binary.LittleEndian.Uint16(b[0:2]))
	if len(b) < size+2 {
		return Dir{}, 0, fmt.Errorf("buffer too short for dir size %d", size)
	}

	data := b[2 : 2+size]
	d := Dir{}

	if len(data) < 39 {
		return d, 0, fmt.Errorf("stat too short")
	}

	d.Type = binary.LittleEndian.Uint16(data[0:2])
	d.Dev = binary.LittleEndian.Uint32(data[2:6])

	d.Qid.Type = data[6]
	d.Qid.Vers = binary.LittleEndian.Uint32(data[7:11])
	d.Qid.Path = binary.LittleEndian.Uint64(data[11:19])

	d.Mode = binary.LittleEndian.Uint32(data[19:23])
	d.Atime = binary.LittleEndian.Uint32(data[23:27])
	d.Mtime = binary.LittleEndian.Uint32(data[27:31])
	d.Length = binary.LittleEndian.Uint64(data[31:39])

	off := 39
	var n int

	d.Name, n = gStrN(data[off:])
	off += n
	d.Uid, n = gStrN(data[off:])
	off += n
	d.Gid, n = gStrN(data[off:])
	off += n
	d.Muid, n = gStrN(data[off:])
	off += n

	return d, 2 + size, nil
}

// --- Fcall ---

// Fcall is the generic 9P message container.
type Fcall struct {
	Size uint32
	Type uint8
	Tag  uint16

	Msize   uint32 // Tversion, Rversion
	Version string // Tversion, Rversion

	Afid  uint32 // Tauth, Tattach
	Uname string // Tauth, Tattach
	Aname string // Tauth, Tattach

	Ename string // Rerror

	Oldtag uint16 // Tflush

	Fid    uint32 // Tattach, Twalk, Topen, Tcreate, Tread, Twrite, Tclunk, Tremove, Tstat, Twstat
	Newfid uint32 // Twalk

	Wname []string // Twalk
	Wqid  []Qid    // Rwalk

	Qid    Qid    // Rattach, Ropen, Rcreate
	Iounit uint32 // Ropen, Rcreate

	Mode uint8  // Topen, Tcreate
	Perm uint32 // Tcreate
	Name string // Tcreate

	Offset uint64 // Tread, Twrite
	Count  uint32 // Tread, Twrite, Rread, Rwrite
	Data   []byte // Rread, Twrite

	Stat []byte // Twstat, Rstat
}

func (f *Fcall) String() string {
	return fmt.Sprintf("Fcall{Type:%d, Tag:%d, Fid:%d}", f.Type, f.Tag, f.Fid)
}

// --- Encoding ---

// Bytes returns the wire format of the Fcall.
func (f *Fcall) Bytes() ([]byte, error) {
	body, err := f.marshalBody()
	if err != nil {
		return nil, err
	}

	size := 4 + 1 + 2 + len(body)
	buf := make([]byte, size)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(size))
	buf[4] = f.Type
	binary.LittleEndian.PutUint16(buf[5:7], f.Tag)
	copy(buf[7:], body)

	return buf, nil
}

func (f *Fcall) marshalBody() ([]byte, error) {
	b := make([]byte, 0, 1024)

	switch f.Type {
	case Tversion, Rversion:
		b = p32(b, f.Msize)
		b = pStr(b, f.Version)
	case Tauth:
		b = p32(b, f.Afid)
		b = pStr(b, f.Uname)
		b = pStr(b, f.Aname)
	case Rauth:
		b = pQid(b, f.Qid)
	case Rerror:
		b = pStr(b, f.Ename)
	case Tflush:
		b = p16(b, f.Oldtag)
	case Rflush:
		// empty body
	case Tattach:
		b = p32(b, f.Fid)
		b = p32(b, f.Afid)
		b = pStr(b, f.Uname)
		b = pStr(b, f.Aname)
	case Rattach:
		b = pQid(b, f.Qid)
	case Twalk:
		b = p32(b, f.Fid)
		b = p32(b, f.Newfid)
		b = p16(b, uint16(len(f.Wname)))
		for _, w := range f.Wname {
			b = pStr(b, w)
		}
	case Rwalk:
		b = p16(b, uint16(len(f.Wqid)))
		for _, q := range f.Wqid {
			b = pQid(b, q)
		}
	case Topen:
		b = p32(b, f.Fid)
		b = append(b, f.Mode)
	case Ropen, Rcreate:
		b = pQid(b, f.Qid)
		b = p32(b, f.Iounit)
	case Tcreate:
		b = p32(b, f.Fid)
		b = pStr(b, f.Name)
		b = p32(b, f.Perm)
		b = append(b, f.Mode)
	case Tread:
		b = p32(b, f.Fid)
		b = p64(b, f.Offset)
		b = p32(b, f.Count)
	case Rread:
		b = p32(b, uint32(len(f.Data)))
		b = append(b, f.Data...)
	case Twrite:
		b = p32(b, f.Fid)
		b = p64(b, f.Offset)
		b = p32(b, uint32(len(f.Data)))
		b = append(b, f.Data...)
	case Rwrite:
		b = p32(b, f.Count)
	case Tclunk, Tremove, Tstat:
		b = p32(b, f.Fid)
	case Rclunk, Rremove, Rwstat:
		// empty body
	case Rstat:
		b = p16(b, uint16(len(f.Stat)))
		b = append(b, f.Stat...)
	case Twstat:
		b = p32(b, f.Fid)
		b = p16(b, uint16(len(f.Stat)))
		b = append(b, f.Stat...)
	default:
		return nil, errors.New("unknown message type")
	}
	return b, nil
}

// --- Decoding ---

// ReadFcall reads a single 9P message from r.
func ReadFcall(r io.Reader) (*Fcall, error) {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, sizeBuf); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(sizeBuf)

	if size < 7 {
		return nil, fmt.Errorf("message too short: %d", size)
	}

	buf := make([]byte, size-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return Unmarshal(buf, size)
}

// Unmarshal decodes the body (type + tag + params).
func Unmarshal(buf []byte, size uint32) (*Fcall, error) {
	if len(buf) < 3 {
		return nil, errors.New("buffer too short header")
	}

	f := &Fcall{Size: size}
	f.Type = buf[0]
	f.Tag = binary.LittleEndian.Uint16(buf[1:3])

	body := buf[3:]

	var err error
	switch f.Type {
	case Tversion, Rversion:
		f.Msize, body = g32(body)
		f.Version, body = gStr(body)
	case Tauth:
		f.Afid, body = g32(body)
		f.Uname, body = gStr(body)
		f.Aname, body = gStr(body)
	case Rauth:
		f.Qid, body = gQid(body)
	case Rerror:
		f.Ename, body = gStr(body)
	case Tflush:
		f.Oldtag, body = g16(body)
	case Rflush:
	case Tattach:
		f.Fid, body = g32(body)
		f.Afid, body = g32(body)
		f.Uname, body = gStr(body)
		f.Aname, body = gStr(body)
	case Rattach:
		f.Qid, body = gQid(body)
	case Twalk:
		f.Fid, body = g32(body)
		f.Newfid, body = g32(body)
		var n uint16
		n, body = g16(body)
		f.Wname = make([]string, n)
		for i := 0; i < int(n); i++ {
			f.Wname[i], body = gStr(body)
		}
	case Rwalk:
		var n uint16
		n, body = g16(body)
		f.Wqid = make([]Qid, n)
		for i := 0; i < int(n); i++ {
			f.Wqid[i], body = gQid(body)
		}
	case Topen:
		f.Fid, body = g32(body)
		if len(body) > 0 {
			f.Mode = body[0]
			body = body[1:]
		}
	case Ropen, Rcreate:
		f.Qid, body = gQid(body)
		f.Iounit, body = g32(body)
	case Tcreate:
		f.Fid, body = g32(body)
		f.Name, body = gStr(body)
		f.Perm, body = g32(body)
		if len(body) > 0 {
			f.Mode = body[0]
			body = body[1:]
		}
	case Tread:
		f.Fid, body = g32(body)
		f.Offset, body = g64(body)
		f.Count, body = g32(body)
	case Rread:
		var count uint32
		count, body = g32(body)
		if uint32(len(body)) < count {
			count = uint32(len(body))
		}
		f.Data = make([]byte, count)
		copy(f.Data, body[:count])
		body = body[count:]
	case Twrite:
		f.Fid, body = g32(body)
		f.Offset, body = g64(body)
		var count uint32
		count, body = g32(body)
		if uint32(len(body)) < count {
			count = uint32(len(body))
		}
		f.Data = make([]byte, count)
		copy(f.Data, body[:count])
		body = body[count:]
	case Rwrite:
		f.Count, body = g32(body)
	case Tclunk, Tremove, Tstat:
		f.Fid, body = g32(body)
	case Rclunk, Rremove, Rwstat:
	case Rstat:
		var n uint16
		n, body = g16(body)
		f.Stat = make([]byte, n)
		copy(f.Stat, body[:n])
		body = body[n:]
	case Twstat:
		f.Fid, body = g32(body)
		var n uint16
		n, body = g16(body)
		f.Stat = make([]byte, n)
		copy(f.Stat, body[:n])
		body = body[n:]
	default:
		return nil, fmt.Errorf("unknown type: %d", f.Type)
	}

	return f, err
}

// --- Helpers (encoding) ---

func p16(b []byte, v uint16) []byte {
	t := make([]byte, 2)
	binary.LittleEndian.PutUint16(t, v)
	return append(b, t...)
}

func p32(b []byte, v uint32) []byte {
	t := make([]byte, 4)
	binary.LittleEndian.PutUint32(t, v)
	return append(b, t...)
}

func p64(b []byte, v uint64) []byte {
	t := make([]byte, 8)
	binary.LittleEndian.PutUint64(t, v)
	return append(b, t...)
}

func pStr(b []byte, s string) []byte {
	l := uint16(len(s))
	b = p16(b, l)
	return append(b, s...)
}

func pQid(b []byte, q Qid) []byte {
	b = append(b, q.Type)
	b = p32(b, q.Vers)
	b = p64(b, q.Path)
	return b
}

func pStrBuf(b []byte, s string) int {
	l := uint16(len(s))
	binary.LittleEndian.PutUint16(b[0:2], l)
	copy(b[2:], s)
	return 2 + int(l)
}

// --- Helpers (decoding) ---

func g16(b []byte) (uint16, []byte) {
	if len(b) < 2 {
		return 0, b
	}
	v := binary.LittleEndian.Uint16(b)
	return v, b[2:]
}

func g32(b []byte) (uint32, []byte) {
	if len(b) < 4 {
		return 0, b
	}
	v := binary.LittleEndian.Uint32(b)
	return v, b[4:]
}

func g64(b []byte) (uint64, []byte) {
	if len(b) < 8 {
		return 0, b
	}
	v := binary.LittleEndian.Uint64(b)
	return v, b[8:]
}

func gStr(b []byte) (string, []byte) {
	if len(b) < 2 {
		return "", b
	}
	l := binary.LittleEndian.Uint16(b)
	b = b[2:]
	if len(b) < int(l) {
		return "", b
	}
	s := string(b[:l])
	return s, b[l:]
}

func gStrN(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	l := int(binary.LittleEndian.Uint16(b[0:2]))
	if len(b) < 2+l {
		return "", 0
	}
	return string(b[2 : 2+l]), 2 + l
}

func gQid(b []byte) (Qid, []byte) {
	if len(b) < 13 {
		return Qid{}, b
	}
	q := Qid{}
	q.Type = b[0]
	q.Vers = binary.LittleEndian.Uint32(b[1:5])
	q.Path = binary.LittleEndian.Uint64(b[5:13])
	return q, b[13:]
}
