// qid.go defines the Qid type for unique file identification.
// Qid contains type, version, and path fields.
package p9

// Qid Type Constants (High 8 bits of Mode)
const (
	QTDIR    = 0x80
	QTAPPEND = 0x40
	QTEXCL   = 0x20
	QTMOUNT  = 0x10
	QTAUTH   = 0x08
	QTTMP    = 0x04
	QTFILE   = 0x00
)
