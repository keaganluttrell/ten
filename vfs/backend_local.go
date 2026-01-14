package vfs

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// LocalBackend implements Backend using the local filesystem.
type LocalBackend struct {
	Root string
}

func NewLocalBackend(root string) (*LocalBackend, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// Warning: MkdirAll might fail if path is a mount point that is RO?
	// But /data is RW.
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
	log.Printf("List: path=%s -> localPath=%s", path, localPath)
	entries, err := os.ReadDir(localPath)
	if err != nil {
		log.Printf("List: ReadDir failed: %v", err)
		return nil, err
	}

	log.Printf("List: Found %d entries", len(entries))
	var dirs []p9.Dir
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		log.Printf("  - %s", info.Name())
		dirs = append(dirs, fileInfoToDir(info))
	}
	log.Printf("List: Returning %d dirs", len(dirs))
	return dirs, nil
}

func (b *LocalBackend) Open(path string, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	// Map 9P mode to os flags
	// 9P: 0=Read, 1=Write, 2=RDWR
	// We default to O_RDWR unless specifically ReadOnly,
	// but Plan 9 Topen specifies mode.
	flag := os.O_RDWR
	if mode == 0 {
		flag = os.O_RDONLY
	} else if mode == 1 {
		flag = os.O_WRONLY
	}
	// O_CREATE is handled in Create(), not Open()

	f, err := os.OpenFile(localPath, flag, 0)
	if err != nil {
		return nil, err
	}

	// Check if directory
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if fi.IsDir() {
		return &DirHandle{f: f}, nil
	}
	return f, nil
}

func (b *LocalBackend) Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	// If perm has DMDIR, mkdir
	if perm&p9.DMDIR != 0 {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return nil, err
		}
		f, err := os.Open(localPath)
		if err != nil {
			return nil, err
		}
		return &DirHandle{f: f}, nil
	}

	return os.Create(localPath)
}

func (b *LocalBackend) Remove(path string) error {
	return os.Remove(b.toLocal(path))
}

func (b *LocalBackend) Rename(oldPath, newPath string) error {
	return os.Rename(b.toLocal(oldPath), b.toLocal(newPath))
}

func (b *LocalBackend) Chmod(path string, mode uint32) error {
	return os.Chmod(b.toLocal(path), os.FileMode(mode&0777))
}

func (b *LocalBackend) Truncate(path string, size int64) error {
	return os.Truncate(b.toLocal(path), size)
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

// DirHandle wraps a directory file to provide 9P read semantics
// DirHandle wraps a directory file to provide 9P read semantics
type DirHandle struct {
	f      *os.File
	offset int64
	data   []byte
	loaded bool
}

func (d *DirHandle) Read(p []byte) (n int, err error) {
	if !d.loaded {
		log.Printf("DirHandle: Reading directory %s", d.f.Name())
		dirs, err := d.f.Readdir(-1)
		if err != nil && err != io.EOF {
			log.Printf("DirHandle: Readdir failed: %v", err)
			return 0, err
		}

		log.Printf("DirHandle: Found %d entries", len(dirs))
		for _, fi := range dirs {
			log.Printf("  - %s", fi.Name())
			p9d := fileInfoToDir(fi)
			d.data = append(d.data, p9d.Bytes()...)
		}
		d.loaded = true
	}

	if d.offset >= int64(len(d.data)) {
		return 0, io.EOF
	}

	n = copy(p, d.data[d.offset:])
	d.offset += int64(n)
	log.Printf("DirHandle: Read returning %d bytes (offset %d/%d)", n, d.offset, len(d.data))
	return n, nil
}

func (d *DirHandle) Write(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF // Directories are read-only for data
}

func (d *DirHandle) Close() error {
	return d.f.Close()
}
