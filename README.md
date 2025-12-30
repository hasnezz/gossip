# UDP Gossip Node

A lightweight, fault-tolerant peer-to-peer node framework over UDP, implementing heartbeat-based peer discovery, gossip propagation, and HMAC-signed messaging. Designed as a foundation for distributed consensus experiments and minimal Raft-like systems.

## Features

* UDP-based communication for low-latency, connectionless messaging
* Peer discovery and heartbeat gossip with automatic dead peer detection
* HMAC-signed JSON messages for message authenticity
* Simple node structure with follower/candidate/leader roles
* Concurrency-safe peer list management

## Getting Started

### Prerequisites

* Go 1.21+
* `go.uber.org/zap` for logging

### Build

```bash
go build -o gossip-node cmd/main.go
```

### Run

```bash
# Start first node
./gossip-node -addr 127.0.0.1:4100

# Start second node with first node as seed
./gossip-node -addr 127.0.0.1:4101 -seed 127.0.0.1:4100
```

### Usage

* Nodes automatically exchange heartbeat messages and gossip peer lists.
* Dead peers are automatically detected using `DeadPeerThreshold`.
* Future updates may include leader election and log replication.

## Code Overview

* `Node` — Represents a node with ID, role, and peer list
* `Peer` — Represents a peer node with last seen timestamp
* `Message` — HMAC-signed JSON messages for communication
* `HBDetails` — Heartbeat payload including peer information
* `hearbeat()` — Periodically sends heartbeats to all known peers
* `recvloop()` — Listens for incoming messages and updates peers
