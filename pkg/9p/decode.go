package p9

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ReadFcall reads a single 9P message from r.
func ReadFcall(r io.Reader) (*Fcall, error) {
	// Read Size (4 bytes)
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, sizeBuf); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(sizeBuf)

	if size < 7 { // min size: size[4] + type[1] + tag[2]
		return nil, fmt.Errorf("message too short: %d", size)
	}

	// Read remaining bytes (Size - 4)
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
	case Rclunk, Rremove:
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

// Helpers

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
