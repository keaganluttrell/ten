package p9

import (
	"fmt"
)

// Message Types
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

// Permissions
const (
	DMDIR    = 0x80000000
	DMAPPEND = 0x40000000
	DMEXCL   = 0x20000000
	DMMOUNT  = 0x10000000
	DMAUTH   = 0x08000000
	DMTMP    = 0x04000000
)

// Qid represents a unique file ID on the server
type Qid struct {
	Type    uint8
	Vers    uint32
	Path    uint64
}

// Fcall is the generic 9P message container
type Fcall struct {
	Size    uint32
	Type    uint8
	Tag     uint16
	
	// Fields specific to message types are flattened here for simplicity (Plan 9 style)
	// or we can use specific structs. To keep it compatible with 'go9p' styles often used:
	
	Msize   uint32 // Tversion, Rversion
	Version string // Tversion, Rversion
	
	Afid    uint32 // Tauth, Tattach
	Uname   string // Tauth, Tattach
	Aname   string // Tauth, Tattach
	
	Ename   string // Rerror
	
	Oldtag  uint16 // Tflush
	
	Fid     uint32 // Tattach, Twalk, Topen, Tcreate, Tread, Twrite, Tclunk, Tremove, Tstat, Twstat
	Newfid  uint32 // Twalk
	
	Wname   []string // Twalk
	Wqid    []Qid    // Rwalk
	
	Qid     Qid      // Rattach, Ropen, Rcreate
	Iounit  uint32   // Ropen, Rcreate
	
	Mode    uint8    // Topen, Tcreate
	Perm    uint32   // Tcreate
	Name    string   // Tcreate
	
	Offset  uint64   // Tread, Twrite
	Count   uint32   // Tread, Twrite, Rread, Rwrite
	Data    []byte   // Rread, Twrite
	
	Stat    []byte   // Twstat, Rstat
}

// String provides a debug representation
func (f *Fcall) String() string {
	return fmt.Sprintf("Fcall{Type:%d, Tag:%d, Fid:%d}", f.Type, f.Tag, f.Fid)
}
