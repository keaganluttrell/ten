package vfs

import (
	"io"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Backend abstracts the storage layer.
// Since we use FUSE, the main implementation is LocalBackend (os calls).
type Backend interface {
	Stat(path string) (p9.Dir, error)
	List(path string) ([]p9.Dir, error)
	Open(path string, mode uint8) (io.ReadWriteCloser, error)
	Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error)
	Remove(path string) error
	Rename(oldPath, newPath string) error
	Chmod(path string, mode uint32) error
	Truncate(path string, size int64) error
}
