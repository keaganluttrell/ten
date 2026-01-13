// stat.go defines the Stat type for file metadata.
package p9

import (
	"encoding/binary"
	"fmt"
)

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
	// Calculate size first
	// size[2] type[2] dev[4] qid[13] mode[4] atime[4] mtime[4] length[8] name[s] uid[s] gid[s] muid[s]
	// Fixed size: 2+4+13+4+4+4+8 = 39 bytes
	// Strings: 2+len each

	size := 39 +
		(2 + len(d.Name)) +
		(2 + len(d.Uid)) +
		(2 + len(d.Gid)) +
		(2 + len(d.Muid))

	b := make([]byte, 2+size)

	// Total size includes the size field itself?
	// Spec: "n[2] ... n bytes of data"
	// The "stat" message in Rstat is n[2] stat[n].
	// Inside stat[n], we have a sequence of directory entries.
	// Each directory entry starts with size[2].
	// The size includes itself.

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

func pStrBuf(b []byte, s string) int {
	l := uint16(len(s))
	binary.LittleEndian.PutUint16(b[0:2], l)
	copy(b[2:], s)
	return 2 + int(l)
}

// UnmarshalDir decodes a single Dir from the buffer.
// Returns the Dir, the number of bytes consumed, and any error.
func UnmarshalDir(b []byte) (Dir, int, error) {
	if len(b) < 2 {
		return Dir{}, 0, fmt.Errorf("buffer too short")
	}

	size := int(binary.LittleEndian.Uint16(b[0:2]))
	if len(b) < size+2 {
		return Dir{}, 0, fmt.Errorf("buffer too short for dir size %d", size)
	}

	// Adjust buffer to point to content
	data := b[2 : 2+size]
	// But wait, common practice: size is size of the following bytes.
	// Spec: "DIR entry: size[2] contents..."
	// contents size matches size[2].

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
