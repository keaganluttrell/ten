# Specification: pkg/9p

## Inherited Context
From Root `SPECIFICATION.md`: This module implements the 9P2000 protocol used by the entire system. It must be a pure, dependency-free library.

## Role in Project Ten
This is the **shared language** all components speak. Kernel, VFS-Service, SSR, and Factotum all import `pkg/9p` for encoding and decoding messages.

---

## Message Types (Constants)

| T-Message | Value | R-Message | Value |
| :--- | :--- | :--- | :--- |
| Tversion | 100 | Rversion | 101 |
| Tauth | 102 | Rauth | 103 |
| Tattach | 104 | Rattach | 105 |
| — | 106 | Rerror | 107 |
| Tflush | 108 | Rflush | 109 |
| Twalk | 110 | Rwalk | 111 |
| Topen | 112 | Ropen | 113 |
| Tcreate | 114 | Rcreate | 115 |
| Tread | 116 | Rread | 117 |
| Twrite | 118 | Rwrite | 119 |
| Tclunk | 120 | Rclunk | 121 |
| Tremove | 122 | Rremove | 123 |
| Tstat | 124 | Rstat | 125 |
| Twstat | 126 | Rwstat | 127 |

*Note: Type 106 (Terror) is not used. Errors are always R-messages.*

---

## Core Structures

### Qid (Unique File Identifier)
```text
type: 1 byte   — QTDIR (0x80), QTAPPEND (0x40), QTEXCL (0x20), QTAUTH (0x08), QTFILE (0x00)
vers: 4 bytes  — Version number (increments on change)
path: 8 bytes  — Unique file ID on server
```

### Stat (File Metadata)
```text
size:    2 bytes  — Total size of stat (excluding this field)
type:    2 bytes  — Server type
dev:     4 bytes  — Server subtype
qid:     13 bytes — Qid structure
mode:    4 bytes  — Permissions and flags
atime:   4 bytes  — Last access time (seconds since epoch)
mtime:   4 bytes  — Last modification time
length:  8 bytes  — File length in bytes
name:    string   — File name
uid:     string   — Owner name
gid:     string   — Group name
muid:    string   — Last modifier name
```

---

## Wire Format

All data is **little-endian**.

### Integers
| Type | Size | Encoding |
| :--- | :--- | :--- |
| uint8 | 1 byte | Direct |
| uint16 | 2 bytes | Little-endian |
| uint32 | 4 bytes | Little-endian |
| uint64 | 8 bytes | Little-endian |

### Strings
```text
[2-byte length (little-endian)][UTF-8 bytes]
```
*No null terminator.*

### Arrays (e.g., wname in Twalk)
```text
[2-byte count][element 0][element 1]...
```

### Message Envelope
```text
[4-byte size][1-byte type][2-byte tag][...payload...]
```
*Size includes the size field itself.*

---

## Message Definitions

### Tversion / Rversion
```text
Tversion: size[4] type[1]=100 tag[2] msize[4] version[s]
Rversion: size[4] type[1]=101 tag[2] msize[4] version[s]
```

### Tauth / Rauth *
```text
Tauth: size[4] type[1]=102 tag[2] afid[4] uname[s] aname[s]
Rauth: size[4] type[1]=103 tag[2] aqid[13]
```
**\* Note:** Project Ten skips `Tauth`. We use file-based tickets in `Tattach.aname` instead. These definitions are included for protocol completeness.

### Tattach / Rattach
```text
Tattach: size[4] type[1]=104 tag[2] fid[4] afid[4] uname[s] aname[s]
Rattach: size[4] type[1]=105 tag[2] qid[13]
```

### Rerror
```text
Rerror: size[4] type[1]=107 tag[2] ename[s]
```

### Tflush / Rflush
```text
Tflush: size[4] type[1]=108 tag[2] oldtag[2]
Rflush: size[4] type[1]=109 tag[2]
```

### Twalk / Rwalk
```text
Twalk: size[4] type[1]=110 tag[2] fid[4] newfid[4] nwname[2] wname[s]...
Rwalk: size[4] type[1]=111 tag[2] nwqid[2] wqid[13]...
```

### Topen / Ropen
```text
Topen: size[4] type[1]=112 tag[2] fid[4] mode[1]
Ropen: size[4] type[1]=113 tag[2] qid[13] iounit[4]
```

### Tcreate / Rcreate
```text
Tcreate: size[4] type[1]=114 tag[2] fid[4] name[s] perm[4] mode[1]
Rcreate: size[4] type[1]=115 tag[2] qid[13] iounit[4]
```

### Tread / Rread
```text
Tread: size[4] type[1]=116 tag[2] fid[4] offset[8] count[4]
Rread: size[4] type[1]=117 tag[2] count[4] data[count]
```

### Twrite / Rwrite
```text
Twrite: size[4] type[1]=118 tag[2] fid[4] offset[8] count[4] data[count]
Rwrite: size[4] type[1]=119 tag[2] count[4]
```

### Tclunk / Rclunk
```text
Tclunk: size[4] type[1]=120 tag[2] fid[4]
Rclunk: size[4] type[1]=121 tag[2]
```

### Tremove / Rremove
```text
Tremove: size[4] type[1]=122 tag[2] fid[4]
Rremove: size[4] type[1]=123 tag[2]
```

### Tstat / Rstat
```text
Tstat: size[4] type[1]=124 tag[2] fid[4]
Rstat: size[4] type[1]=125 tag[2] stat[n]
```
*`stat[n]` is the full Stat structure prefixed with a 2-byte size.*

### Twstat / Rwstat
```text
Twstat: size[4] type[1]=126 tag[2] fid[4] stat[n]
Rwstat: size[4] type[1]=127 tag[2]
```

---

## Open Mode Flags

Used in `Topen.mode` and `Tcreate.mode`:

| Flag | Value | Description |
| :--- | :--- | :--- |
| OREAD | 0x00 | Open for read |
| OWRITE | 0x01 | Open for write |
| ORDWR | 0x02 | Open for read/write |
| OEXEC | 0x03 | Open for execute |
| OTRUNC | 0x10 | Truncate file |
| ORCLOSE | 0x40 | Remove on close |

## Inputs
*   **Go Structs**: All message types above.
*   **Byte Slices**: Raw binary data from WebSocket/TCP.

## Outputs
*   **Encoded Bytes**: Strict 9P2000 wire format.
*   **Decoded Structs**: Go objects ready for processing.
*   **Errors**: Standard Go errors for malformed packets.

## Dependencies
*   **Standard Library Only**: `encoding/binary`, `io`, `fmt`, `errors`.

## Constraints
1.  **Zero Network Code**: This package does NOT know about TCP or WebSocket.
2.  **Safety**: Handle malformed inputs gracefully (no panics).
3.  **Performance**: Minimize allocations (reuse buffers where possible).
4.  **Strict Compliance**: Byte-for-byte compatible with Plan 9.

---

## Inner Modules
*   `fcall.go`: Struct definitions and constants.
*   `qid.go`: Qid type and encoding.
*   `stat.go`: Stat type and encoding.
*   `encode.go`: Marshal logic (struct → bytes).
*   `decode.go`: Unmarshal logic (bytes → struct).
