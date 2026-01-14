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
