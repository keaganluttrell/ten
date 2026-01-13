package p9

import (
	"encoding/binary"
	"errors"
)

// Bytes returns the wire format of the Fcall.
// Format: size[4] type[1] tag[2] body[...]
func (f *Fcall) Bytes() ([]byte, error) {
	// First calculate size
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
	// This is a simplified marshaller for v1.
	// In a real implementation this would use a buffer pool and be more efficient.

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
	case Rclunk, Rremove:
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

// Helpers

func p16(b []byte, v uint16) []byte {
	// append 2 bytes
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
