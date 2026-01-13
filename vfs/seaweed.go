package vfs

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Backend abstracts the storage layer (SeaweedFS, S3, or Local).
type Backend interface {
	Stat(path string) (p9.Dir, error)
	List(path string) ([]p9.Dir, error)
	Open(path string, mode uint8) (io.ReadWriteCloser, error)
	Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error)
	Remove(path string) error
}

// LocalBackend implements Backend using the local filesystem.
type LocalBackend struct {
	Root string
}

func NewLocalBackend(root string) (*LocalBackend, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0755); err != nil {
		return nil, err
	}
	return &LocalBackend{Root: abs}, nil
}

func (b *LocalBackend) toLocal(path string) string {
	// Prevent directory traversal
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "..") {
		return filepath.Join(b.Root, "invalid")
	}
	return filepath.Join(b.Root, clean)
}

func (b *LocalBackend) Stat(path string) (p9.Dir, error) {
	localPath := b.toLocal(path)
	fi, err := os.Stat(localPath)
	if err != nil {
		return p9.Dir{}, err
	}
	return fileInfoToDir(fi), nil
}

func (b *LocalBackend) List(path string) ([]p9.Dir, error) {
	localPath := b.toLocal(path)
	entries, err := os.ReadDir(localPath)
	if err != nil {
		return nil, err
	}

	var dirs []p9.Dir
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		dirs = append(dirs, fileInfoToDir(info))
	}
	return dirs, nil
}

func (b *LocalBackend) Open(path string, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	// Map 9P mode to os flags (O_RDONLY etc)
	// Simplified:
	flag := os.O_RDWR // Default to RW
	if mode == 0 {    // O_RDONLY? Plan 9 modes are: 0=Read, 1=Write, 2=RDWR
		flag = os.O_RDONLY
	} else if mode == 1 {
		flag = os.O_WRONLY
	}

	return os.OpenFile(localPath, flag, 0)
}

func (b *LocalBackend) Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	// If perm has DMDIR, mkdir
	if perm&p9.DMDIR != 0 {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return nil, err
		}
		return nil, nil // Directories don't return an FD on create in Go usually, but 9P expects an open FID?
		// Actually Tcreate returns an open FID.
		// For directories, we just open it for reading.
	}

	return os.Create(localPath)
}

func (b *LocalBackend) Remove(path string) error {
	return os.Remove(b.toLocal(path))
}

func fileInfoToDir(fi os.FileInfo) p9.Dir {
	mode := uint32(fi.Mode() & 0777)
	qidType := uint8(p9.QTFILE)

	if fi.IsDir() {
		mode |= p9.DMDIR
		qidType = p9.QTDIR
	}

	return p9.Dir{
		Type: 0,
		Dev:  0,
		Qid: p9.Qid{
			Type: qidType,
			Vers: 0,
			Path: uint64(fi.ModTime().UnixNano()), // Hacky unique ID
		},
		Mode:   mode,
		Atime:  uint32(fi.ModTime().Unix()),
		Mtime:  uint32(fi.ModTime().Unix()),
		Length: uint64(fi.Size()),
		Name:   fi.Name(),
		Uid:    "user",
		Gid:    "group",
		Muid:   "user",
	}
}
