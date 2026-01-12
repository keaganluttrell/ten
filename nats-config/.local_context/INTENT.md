# Intent: nats-config (Event Bus Configuration)

## Vision
NATS is the event bus. SeaweedFS publishes. VFS-Service subscribes. This folder contains the configuration.

## Responsibilities
1.  **NATS Server Config**: Ports, JetStream storage settings.
2.  **Stream Definition**: The `FILESYSTEM` stream for file change events.

## Constraints
*   **Not Code**: This is infrastructure configuration only.
*   **Required for Real-Time**: VFS-Service depends on this for blocking reads.

## Interfaces
*   **Input**: SeaweedFS Filer (publishes events).
*   **Output**: VFS-Service (subscribes to events).
