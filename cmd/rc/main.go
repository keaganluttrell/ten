package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

var (
	kernelAddr = flag.String("kernel", "127.0.0.1:9000", "Kernel address")
	user       = flag.String("user", "glenda", "User name")
)

type Shell struct {
	client *kernel.Client
	cwd    string
	cwdFid uint32
}

func main() {
	flag.Parse()

	fmt.Printf("Connecting to Kernel at %s...\n", *kernelAddr)

	dialer := kernel.NewNetworkDialer()
	client, err := dialer.Dial(*kernelAddr)
	if err != nil {
		log.Fatalf("Failed to dial kernel: %v", err)
	}
	defer client.Close()

	// Negotiate Version
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		log.Fatalf("Version negotiation failed: %v", err)
	}

	rootFid := client.NextFid()
	attachReq := &p9.Fcall{
		Type:  p9.Tattach,
		Fid:   rootFid,
		Afid:  p9.NOFID,
		Uname: *user,
		Aname: "/",
	}
	if _, err := client.RPC(attachReq); err != nil {
		log.Fatalf("Attach failed: %v", err)
	}
	fmt.Printf("Connected as user '%s'\n", *user)

	shell := &Shell{
		client: client,
		cwd:    "/",
		cwdFid: rootFid,
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s %% ", shell.cwd)
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		args := strings.Fields(line)
		cmd := args[0]

		switch cmd {
		case "exit":
			return
		case "cd":
			if len(args) > 1 {
				shell.cd(args[1])
			} else {
				shell.cd("/")
			}
		case "ls":
			p := shell.cwd
			if len(args) > 1 {
				p = shell.absPath(args[1])
			}
			shell.ls(p)
		case "cat":
			if len(args) > 1 {
				shell.cat(shell.absPath(args[1]))
			} else {
				fmt.Println("Usage: cat <file>")
			}
		case "echo":
			if len(args) >= 3 && args[len(args)-2] == ">" {
				content := strings.Join(args[1:len(args)-2], " ")
				target := shell.absPath(args[len(args)-1])
				shell.write(target, content)
			} else {
				fmt.Println(strings.Join(args[1:], " "))
			}
		case "bind":
			if len(args) < 3 {
				fmt.Println("Usage: bind [-flags] old new")
				continue
			}
			shell.bind(args[1:])
		case "mount":
			if len(args) < 3 {
				fmt.Println("Usage: mount <addr> <old> [flags]")
				continue
			}
			shell.mount(args[1], args[2], args[3:])
		case "mkdir":
			if len(args) < 2 {
				fmt.Println("Usage: mkdir <path>")
				continue
			}
			shell.mkdir(args[1])
		case "touch":
			if len(args) < 2 {
				fmt.Println("Usage: touch <path>")
				continue
			}
			shell.touch(args[1])
		case "rm":
			if len(args) < 2 {
				fmt.Println("Usage: rm <path>")
				continue
			}
			shell.rm(args[1])
		case "chmod":
			if len(args) < 3 {
				fmt.Println("Usage: chmod <mode> <path>")
				continue
			}
			shell.chmod(args[1], args[2])
		case "chown":
			if len(args) < 3 {
				fmt.Println("Usage: chown <user> <path>")
				continue
			}
			shell.chown(args[1], args[2])
		case "cp":
			if len(args) < 3 {
				fmt.Println("Usage: cp <src> <dst>")
				continue
			}
			shell.cp(args[1], args[2])
		default:
			fmt.Printf("rc: %s: command not found\n", cmd)
		}
	}
}

func (s *Shell) absPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	if s.cwd == "/" {
		return "/" + p
	}
	return s.cwd + "/" + p
}

func (s *Shell) cd(p string) {
	target := s.absPath(p)

	// Verify target exists and is a directory
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(target, "/"), "/")
	if target == "/" {
		parts = []string{}
	}

	resp, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts})
	if err != nil {
		fmt.Printf("cd: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	if resp.Type == p9.Rerror {
		fmt.Printf("cd: %s\n", resp.Ename)
		return
	}

	if len(resp.Wqid) != len(parts) {
		fmt.Printf("cd: %s: not found\n", p)
		return
	}

	// Check if directory
	lastQid := p9.Qid{Type: p9.QTDIR} // Default root assumption
	if len(resp.Wqid) > 0 {
		lastQid = resp.Wqid[len(resp.Wqid)-1]
	}

	if lastQid.Type&p9.QTDIR == 0 {
		fmt.Printf("cd: %s: not a directory\n", p)
		return
	}

	// Success
	s.cwd = path.Clean(target)
}

func (s *Shell) ls(p string) {
	fmt.Printf("DEBUG: ls %s detected (BinVer: 1)\n", p)
	fid := s.client.NextFid()
	target := s.absPath(p)
	parts := strings.Split(strings.Trim(target, "/"), "/")
	if target == "/" {
		parts = []string{}
	}

	// Start from root (cwdFid is root)
	resp, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts})
	if err != nil {
		fmt.Printf("ls: %v\n", err)
		return
	}
	if resp.Type == p9.Rerror {
		fmt.Printf("ls: %s\n", resp.Ename)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	if len(resp.Wqid) != len(parts) {
		fmt.Printf("ls: %s not found\n", p)
		return
	}

	// Check Qid type
	lastQid := p9.Qid{Type: p9.QTDIR}
	if len(resp.Wqid) > 0 {
		lastQid = resp.Wqid[len(resp.Wqid)-1]
	}

	if lastQid.Type&p9.QTDIR == 0 {
		// It's a file, just list it
		fmt.Printf("%s\n", parts[len(parts)-1])
		return
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Topen, Fid: fid, Mode: 0}); err != nil {
		fmt.Printf("ls: open failed: %v\n", err)
		return
	}

	offset := uint64(0)
	for {
		resp, err := s.client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil {
			break
		}
		if len(resp.Data) == 0 {
			break
		}

		data := resp.Data
		for len(data) > 0 {
			dir, n, err := p9.UnmarshalDir(data)
			if err != nil {
				break
			}
			suffix := ""
			if dir.Mode&p9.DMDIR != 0 {
				suffix = "/"
			}
			fmt.Printf("%s%s\t", dir.Name, suffix)
			data = data[n:]
		}
		offset += uint64(len(resp.Data))
	}
	fmt.Println()
}

func (s *Shell) cat(p string) {
	fid := s.client.NextFid()
	target := s.absPath(p)
	parts := strings.Split(strings.Trim(target, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("cat: %v\n", err)
		return
	}
	// Note: client.RPC doesn't check Rerror, but Twalk usually doesn't return Rerror on partial walk (just short wqid).
	// But if we are debugging via Rerror...
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Topen, Fid: fid, Mode: 0}); err != nil {
		fmt.Printf("cat: open failed: %v\n", err)
		return
	}

	offset := uint64(0)
	for {
		resp, err := s.client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil {
			break
		}
		if len(resp.Data) == 0 {
			break
		}
		fmt.Print(string(resp.Data))
		offset += uint64(len(resp.Data))
	}
	fmt.Println()
}

func (s *Shell) write(p, content string) {
	fid := s.client.NextFid()
	target := s.absPath(p)
	parts := strings.Split(strings.Trim(target, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("write: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Topen, Fid: fid, Mode: 1}); err != nil { // OWRITE
		fmt.Printf("write: open failed: %v\n", err)
		return
	}

	data := []byte(content)
	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twrite, Fid: fid, Offset: 0, Count: uint32(len(data)), Data: data}); err != nil {
		fmt.Printf("write failed: %v\n", err)
	}
}

func (s *Shell) bind(args []string) {
	cmd := "bind " + strings.Join(args, " ")
	s.write("/dev/sys/ctl", cmd)
}

func (s *Shell) mount(addr, p string, flags []string) {
	cmd := fmt.Sprintf("mount %s %s %s", addr, p, strings.Join(flags, " "))
	s.write("/dev/sys/ctl", cmd)
}

func (s *Shell) mkdir(p string) {
	target := s.absPath(p)
	parent := path.Dir(target)
	base := path.Base(target)

	// Walk to parent
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(parent, "/"), "/")
	if parent == "/" {
		parts = []string{}
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("mkdir: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	// Create
	perm := p9.DMDIR | 0755
	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Tcreate, Fid: fid, Name: base, Perm: uint32(perm), Mode: 0}); err != nil {
		fmt.Printf("mkdir: create failed: %v\n", err)
	}
}

func (s *Shell) touch(p string) {
	target := s.absPath(p)
	parent := path.Dir(target)
	base := path.Base(target)

	// Check if exists first? Or just try create.
	// If we Create existing, 9P spec says it fails.
	// So we should Walk to it first to check existence to support "update mtime" feature or just ignore.
	// For now, let's just try Create.

	// Walk to parent
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(parent, "/"), "/")
	if parent == "/" {
		parts = []string{}
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("touch: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	// Create
	perm := 0644
	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Tcreate, Fid: fid, Name: base, Perm: uint32(perm), Mode: 1}); err != nil {
		// If fail, maybe it exists?
		// We could Twstat to update mtime, but let's accept failure for MVP.
		fmt.Printf("touch: create failed: %v\n", err)
	}
}

func (s *Shell) rm(p string) {
	target := s.absPath(p)
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(target, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("rm: %v\n", err)
		return
	}
	// Tremove implicitly clunks (or invalidates) the fid
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Tremove, Fid: fid}); err != nil {
		fmt.Printf("rm: failed: %v\n", err)
	}
}

func (s *Shell) chmod(modeStr, p string) {
	// Parse mode
	var mode uint32
	// Simple parsing: octal
	fmt.Sscanf(modeStr, "%o", &mode)

	target := s.absPath(p)
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(target, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("chmod: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	// Get current Stat to preserve type/length
	statResp, err := s.client.RPC(&p9.Fcall{Type: p9.Tstat, Fid: fid})
	if err != nil {
		fmt.Printf("chmod: stat failed: %v\n", err)
		return
	}

	dir, _, err := p9.UnmarshalDir(statResp.Stat)
	if err != nil {
		fmt.Printf("chmod: unmarshal failed: %v\n", err)
		return
	}

	// Update Mode
	// Preserve Type bits (DMDIR etc) from old mode and apply new perm bits
	newMode := (dir.Mode &^ 0777) | (mode & 0777)

	// Create request
	dummyDir := p9.Dir{
		Mode:   newMode,
		Length: 0xFFFFFFFFFFFFFFFF, // Ignore
		Mtime:  0xFFFFFFFF,
		Atime:  0xFFFFFFFF,
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twstat, Fid: fid, Stat: dummyDir.Bytes()}); err != nil {
		fmt.Printf("chmod: failed: %v\n", err)
	}
}

func (s *Shell) chown(user, p string) {
	// Plan 9 uses strings for users
	target := s.absPath(p)
	fid := s.client.NextFid()
	parts := strings.Split(strings.Trim(target, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: fid, Wname: parts}); err != nil {
		fmt.Printf("chown: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid})

	dummyDir := p9.Dir{
		Mode:   0xFFFFFFFF,
		Length: 0xFFFFFFFFFFFFFFFF, // Ignore
		Mtime:  0xFFFFFFFF,
		Atime:  0xFFFFFFFF,
		Uid:    user,
		Gid:    "", // Ignore
		Muid:   "", // Ignore
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twstat, Fid: fid, Stat: dummyDir.Bytes()}); err != nil {
		fmt.Printf("chown: failed: %v\n", err)
	}
}

func (s *Shell) cp(srcPath, dstPath string) {
	// Source
	srcTarget := s.absPath(srcPath)
	srcFid := s.client.NextFid()
	srcParts := strings.Split(strings.Trim(srcTarget, "/"), "/")

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: srcFid, Wname: srcParts}); err != nil {
		fmt.Printf("cp: src error: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: srcFid})

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Topen, Fid: srcFid, Mode: 0}); err != nil {
		fmt.Printf("cp: src open failed: %v\n", err)
		return
	}

	// Dest
	dstTarget := s.absPath(dstPath)
	dstParent := path.Dir(dstTarget)
	dstBase := path.Base(dstTarget)

	dstFid := s.client.NextFid()
	dstParts := strings.Split(strings.Trim(dstParent, "/"), "/")
	if dstParent == "/" {
		dstParts = []string{}
	}

	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: s.cwdFid, Newfid: dstFid, Wname: dstParts}); err != nil {
		fmt.Printf("cp: dst parent error: %v\n", err)
		return
	}
	defer s.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: dstFid})

	// Create dest file
	if _, err := s.client.RPC(&p9.Fcall{Type: p9.Tcreate, Fid: dstFid, Name: dstBase, Perm: 0644, Mode: 1}); err != nil {
		fmt.Printf("cp: create failed (overwrite not impl): %v\n", err)
		return
	}

	// Copy Loop
	offset := uint64(0)
	for {
		readResp, err := s.client.RPC(&p9.Fcall{Type: p9.Tread, Fid: srcFid, Offset: offset, Count: 8192})
		if err != nil || len(readResp.Data) == 0 {
			break
		}

		if _, err := s.client.RPC(&p9.Fcall{Type: p9.Twrite, Fid: dstFid, Offset: offset, Count: uint32(len(readResp.Data)), Data: readResp.Data}); err != nil {
			fmt.Printf("cp: write error: %v\n", err)
			break
		}
		offset += uint64(len(readResp.Data))
	}
}
