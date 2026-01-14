# Specification: nats-config (Event Bus Configuration)

## Role
This is **infrastructure configuration**, not a Go module. It configures NATS JetStream to receive events from SeaweedFS Filer.

---

## Purpose

NATS is the **event bus** for Project Ten:
*   SeaweedFS Filer pushes file change events to NATS.
*   VFS-Service subscribes to NATS for real-time directory watching.
*   Enables blocking `Tread` on directories to return when contents change.

---

## Files

| File | Purpose |
| :--- | :--- |
| `nats.conf` | NATS server configuration (ports, JetStream storage). |
| `streams.json` | JetStream stream definition for filesystem events. |

---

## Event Flow

```text
SeaweedFS Filer → NATS (publish) → VFS-Service (subscribe)
                                          ↓
                                   Unblock pending Tread
                                          ↓
                                   Kernel → Browser
```

---

## Constraints

1.  **Infrastructure Only**: No Go code. Just config files.
2.  **JetStream Required**: Persistence for event replay.
3.  **Retention Policy**: Configurable (infinite or rolling window).

---

## No Inner Modules

This is not a Go package. It contains only configuration files.
