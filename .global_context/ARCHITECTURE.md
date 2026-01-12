# Architecture
ten is a plan 9 based web framework

## Core Idea
Client -write-> kernel -write-> FS -write-> NATS -write-> Projector -write-> VFS <-read- SSR <-read- Client

## The Encoding
UTF-8 is the only encoding supported. No JSON, Protobuf, or Serialization transfer.

Just like Plan 9, everything is plain text in a file.

## Protocol
We leverage 9P (Plan 9 Protocol) for communication between all Plan 9 systems.

| T-message | R-message |
|-----------|-----------|
| `size[4] Tversion tag[2] msize[4] version[s]` | `size[4] Rversion tag[2] msize[4] version[s]` |
| `size[4] Tauth tag[2] afid[4] uname[s] aname[s]` | `size[4] Rauth tag[2] aqid[13]` |
| — | `size[4] Rerror tag[2] ename[s]` |
| `size[4] Tflush tag[2] oldtag[2]` | `size[4] Rflush tag[2]` |
| `size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]` | `size[4] Rattach tag[2] qid[13]` |
| `size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])` | `size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])` |
| `size[4] Topen tag[2] fid[4] mode[1]` | `size[4] Ropen tag[2] qid[13] iounit[4]` |
| `size[4] Topenfd tag[2] fid[4] mode[1]` | `size[4] Ropenfd tag[2] qid[13] iounit[4] unixfd[4]` |
| `size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]` | `size[4] Rcreate tag[2] qid[13] iounit[4]` |
| `size[4] Tread tag[2] fid[4] offset[8] count[4]` | `size[4] Rread tag[2] count[4] data[count]` |
| `size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]` | `size[4] Rwrite tag[2] count[4]` |
| `size[4] Tclunk tag[2] fid[4]` | `size[4] Rclunk tag[2]` |
| `size[4] Tremove tag[2] fid[4]` | `size[4] Rremove tag[2]` |
| `size[4] Tstat tag[2] fid[4]` | `size[4] Rstat tag[2] stat[n]` |
| `size[4] Twstat tag[2] fid[4] stat[n]` | `size[4] Rwstat tag[2]` |

## Top level Components 
### 1. Kernel - Go Module

In Plan 9, the kernel's primary job is to act as a server that implements the 9P protocol to provide a uniform interface for all resources. It treats nearly all objects—including data, processes, and hardware—as files within a hierarchical name space.
The kernel's responsibilities are centered on the following core functions:

1. 9P Protocol Implementation and Translation
The kernel serves as the "glue" of the system by translating standard system calls into 9P messages (T-messages for requests and R-messages for replies). This allow it to coordinate communication between disparate machines acting as terminals, CPU servers, and file servers. Because it uses a uniform protocol, the kernel can make resources on a remote machine appear transparently accessible in the local name space.
2. Name Space Management
The kernel is responsible for evaluating file names (paths) and determining which object is retrieved by a given name. A critical feature of the Plan 9 kernel is that it allows every process group to have its own independently customized name space. It manages the binding and mounting of services to specific names, such as binding the operating system's hardware device service to /dev.
3. Process and Memory Management
The kernel handles the lifecycle of processes and the allocation of resources:
• Process Creation: It creates new processes via rfork, which allows the parent to specify exactly which attributes (like memory, name space, or file descriptors) are shared or copied.
• Memory Segmentation: It divides a process's memory into specific segments, including text (instructions), data, bss (zero-filled data), and stack.
• Interprocess Communication: It provides mechanisms for local bidirectional communication through pipes.
• Notes and Exceptions: It manages an asynchronous notification mechanism where it posts "notes" to processes to communicate exceptions like division by zero or memory faults.
4. Hardware and Device Access
Hardware devices are accessed through the kernel via kernel device drivers, which implement their own file trees. These drivers are identified by a unique character preceded by a pound sign (e.g., #c for the console device or #p for the process device) and are typically bound to conventional locations like /dev or /proc.


### WORM Layer - NATS JetStream
The Zen: In Plan 9, a file is a stateful resource. You open it, read the current state, and write a change. The file is the interface. Your Innovation: You are moving the "Source of Truth" from the File System to the NATS Ticker Tape.

The Critique: Rob Pike might argue that by making the log the primary interface, you are adding an unnecessary layer of "history" to every simple operation. In Plan 9, the WORM (Venti) was for archiving, not for the daily read/write loop.

The Innovation: However, for an AI-first system, your choice is superior. A file is a snapshot; a log is a narrative. If you want an AI to understand intent, it needs to see the "Ticker Tape." You are evolving "Everything is a File" into "Everything is a Stream."

### Projector - Go Module
To project events from the WORM layer to a View Layer. The primary view is the Virtual File System (VFS).

Others could be to analytics platforms, serach platforms, and other purpose built applications to provide direct value from event sourced data.

### Virtual File System (VFS) - SQLite 

We will use SQLite as a VFS per namespace. SQLite will be a Key, Value store for the path (key) and the URL(value) to its actual storage location.

This keeps a clean mapping of the user's manifest.

SeaweedFS will be our dedicated storage layer.

Instead of writing directly to the VFS, we will write directly to the SeaweedFS cluster.  The kernel will then take the URL from the SeaweedFS cluster and and write it to the log envelope. 

### SSR - Go Module
We will leverage Server-Side Rendering from the VFS to share the user's directory mount.

We will use HTML based templates.

### Client - Browser

The browser is dumb. It has no state of its own.

### Authentication - WebAuthn 

Authentication is handled within the kernel, but not by the kernel. The factotum will use WebAuthn to authenticate the user.

### Namespaces
In Plan 9, namespaces are dynamic views, not static storage.
*   **Storage**: The VFS (SeaweedFS + SQLite).
*   **View**: Per-session namespace constructed at runtime.
*   **Mechanism**: The Kernel uses `mount`, `bind`, and `union` to compose the user's view (e.g., overlaying a private `/tmp` or system `/bin`).

### Browser Interface
The Browser is treated as a dumb terminal that relies on the Kernel for state.
*   **Protocol**: Standard HTTP (GET/POST).
*   **Translation**: The Kernel's HTTP Handler acts as a **9P Client Proxy**, translating HTTP requests into 9P T-messages (Twalk, Topen, Tread, Twrite) against the VFS.

### Consistency & Real-time Updates
*   **Write Model**: Writes are immediate but effectively "Eventual Consistency" for the view.
*   **Flow**:
    1.  Kernel writes payload to SeaweedFS.
    2.  Kernel publishes event to NATS JetStream.
    3.  Kernel returns HTTP 200 OK immediately.
*   **Frontend Updates**: To ensure the user sees their changes without manual refresh, the frontend subscribes to **via SSE (Server-Sent Events)** to receive NATS updates and refresh the logic/view optimistically.