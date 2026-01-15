# Plan 9 Directory Structure

```text
/
├── acme/          # Acme interactive text window system tools
├── adm/           # Administrative data
│   ├── keys       # Authentication keys
│   ├── timezone   # Timezone tables
│   └── users      # List of users
├── bin/           # Union of architecture-specific binaries
├── boot/          # Initial bootstrap programs
├── dev/           # Hardware and process device interfaces
├── env/           # Environment variables (one file per variable)
├── fd/            # Pseudonyms for open file descriptors (dup)
├── lib/           # System-wide databases and configuration
│   ├── font       # System fonts
│   ├── namespace  # Standard namespace description
│   └── ndb        # Network database
├── mail/          # Electronic mail
│   └── box/       # User mailboxes
├── mnt/           # Standard mount points
├── n/             # Remote file system mount points
├── net/           # Network device and protocol interfaces
│   ├── cs         # Connection server
│   ├── tcp/       # TCP protocol
│   └── udp/       # UDP protocol
├── proc/          # Process debugging interface
├── rc/            # Plan 9 shell data
│   └── bin/       # Shell scripts
├── srv/           # Service registry (rendezvous points)
├── sys/           # System software and source
│   ├── include/   # Header files
│   ├── log/       # System logs
│   ├── man/       # Manual pages
│   └── src/       # Source code for commands and kernel
├── tmp/           # Temporary files (often private per user)
├── usr/           # User home directories
└── $cputype/      # Architecture-specific binaries and libraries (e.g. /386, /amd64)
```

## Description

1. **Core System Root and Mount Points**
    - `/`: Root of the namespace (kernel device root(3)).
    - `/mnt`: Standard mount points for applications.
    - `/n`: Remote file tree imports (e.g., `/n/kremvax`).
    - `/srv`: Service registry for posted descriptors.

2. **Administrative and User Directories**
    - `/adm`: Configuration for users, keys, and time.
    - `/usr`: Home directories.
    - `/tmp`: Temporary storage (typically private).

3. **Executables and Configuration**
    - `/bin`: Union of binary directories.
    - `/rc`: Shell executables and libraries.
    - `/lib`: Non-executable databases (fonts, ndb, namespace).

4. **Hardware and Process Interfaces**
    - `/dev`: Access to devices (console, graphics, mouse).
    - `/proc`: Process control and debugging.
    - `/net`: Network protocols (IP, TCP, UDP).
    - `/fd`: Process file descriptors.
    - `/env`: Environment variables.

5. **Architecture-Specific and Source Directories**
    - `/$cputype`: Machine-dependent headers and libraries.
    - `/sys`: Source code, manual pages, and logs.

6. **Specialized Services**
    - `/mail`: Electronic mail system.
    - `/acme`: Data and guide files for the Acme editor.
    - `/boot`: Initial connection and partition setup logic.

## Starting Point
/
├── adm/
│   └── users          # The Source of Truth for identity.
├── dev/
│   ├── user           # "Who am I?" (Read this to get the current session user).
│   └── cons           # The Browser Console in file form. (Write to it for logs).
├── lib/
│   └── namespace      # The Blueprint. (The most important file in the system).
├── mnt/
│   ├── factotum       # The Auth Gateway. (The RPC file lives here).
│   └── vfs            # The Storage Gateway. (Where the raw SeaweedFS data is mounted).
├── proc/              # The "Heartbeat." (Inspection of active 9P sessions).
└── [content]          # Binds from /mnt/vfs (e.g. /home, /sys, /posts).