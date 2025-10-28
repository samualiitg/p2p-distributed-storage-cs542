# Peer-to-Peer Distributed Storage System (CS542 Course Project)

**Submitted To:** Prof. Diganta Goswami 
**Course:** CS542 - Distributed Systems 
**Institute:** Indian Institute of Technology, Guwahati 

---

## Project Members

| Name                       | Roll Number |
|----------------------------|--------------|
| Ritik Tiwari               | 254101048    |
| Sai Ganesh Chatharasupalli | 254101051    |
| Samual                     | 254101052    |

---

## Project Overview

This project implements a **Peer-to-Peer Distributed Storage System over a LAN**, where multiple peers collaboratively contribute storage resources to achieve **fault tolerance, scalability, and data security**.

Unlike centralized storage systems, this P2P system ensures that no single point of failure can bring down the network — each peer acts as both a storage node and a data replicator. The project showcases core principles of distributed systems, including **peer discovery, replication, fault detection, and consistency maintenance**.

---

## Key Features

- **Peer Discovery via UDP Broadcast** — automatic detection of peers in a LAN. 
- **Secure Communication** — hybrid encryption using **RSA (for key exchange)** and **Fernet (for data encryption)**. 
- **FUSE-based Client File System** — provides a virtual mount point for seamless file access. 
- **Automatic Replication** — ensures file redundancy across multiple peers. 
- **Heartbeat-based Fault Detection** — monitors peer availability in real time. 
- **Metadata Synchronization** — keeps track of file locations and replicas consistently. 

---

## System Architecture (Summary)

1. The **client** broadcasts a storage request to discover available peers. 
2. A **peer** responds with its **RSA public key** and listening **TCP port**. 
3. The **client** establishes a secure **TCP session** through key exchange. 
4. Files written by the client are stored on a **primary peer**. 
5. The **primary peer** automatically **replicates** files to other peers. 
6. Periodic **heartbeats** detect failed peers, and replication ensures data recovery. 

---

## Directory Structure

```
p2p-distributed-storage-cs542/
├── src/
│   ├── client/                 # FUSE client implementation
│   ├── peer/                   # Peer node logic and replication
│   ├── crypto/                 # RSA + Fernet key management
│   ├── network/                # UDP broadcast + TCP communication
│   └── utils/                  # Metadata and helper utilities
├── requirements.txt
├── README.md
└── docs/
    └── architecture-diagram.png
```

---

## Getting Started

### Prerequisites
- Python 3.10+ 
- `fusepy`, `cryptography`, `socket`, `threading` 
- Works on Linux or macOS (FUSE required)

###  Installation
```bash
git clone https://github.com/samualiitg/p2p-distributed-storage-cs542.git
cd p2p-distributed-storage-cs542
pip install -r requirements.txt
```

### Running the System

#### 1. Start Peer Nodes
Each peer runs a storage server process:
```bash
python src/peer/peer_node.py --port 8000 --storage-dir ./peer1_data
python src/peer/peer_node.py --port 8001 --storage-dir ./peer2_data
```

#### 2. Start Client (FUSE Mount)
Mount the virtual file system to interact like a local folder:
```bash
python src/client/client_mount.py --mount ./mnt
```

#### 3. Use Like Normal File System
```bash
cp myfile.txt ./mnt/
cat ./mnt/myfile.txt
rm ./mnt/myfile.txt
```

All operations automatically handle encryption, replication, and metadata synchronization across peers.

---

##  Design Highlights

| Component | Technology / Concept |
|------------|----------------------|
| Peer Discovery | UDP Broadcast |
| Communication | TCP Sockets |
| Encryption | RSA (key exchange) + Fernet (symmetric) |
| Storage | File-based (chunked) |
| Replication | Primary + replica peers |
| Fault Detection | Heartbeat messages |
| Client Interface | FUSE (Python fusepy) |

---

## Testing & Evaluation

- Verified successful peer discovery in local subnet. 
- Tested replication consistency under peer failures. 
- File operations validated through FUSE mount. 
- Future work: integrate DHT-based lookup and dynamic load balancing.

---

## References

- CS542 Distributed Systems course materials. 
- "Peer-to-Peer Systems" — research papers on distributed hash tables (DHTs). 
- FUSE Python library documentation. 
- Cryptography.io library for RSA and Fernet encryption.

---

## Repository

**Project Repository:** 
👉 [https://github.com/samualiitg/p2p-distributed-storage-cs542](https://github.com/samualiitg/p2p-distributed-storage-cs542)

---
