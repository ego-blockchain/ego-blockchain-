# Ego Improvement Proposals (EIPs)

EIPs are the primary mechanism for proposing changes to the Ego Blockchain protocol, standards, and processes. They ensure the network remains 100% decentralized — no single person or team can change the protocol unilaterally.

## Index

| EIP | Title | Status | Category |
|-----|-------|--------|----------|
| [EGO-1](EGO-1.md) | EIP Purpose and Guidelines | Active | Process |
| [EGO-3](EGO-3.md) | Real Estate Token Standard | Final | Standards Track — Interface |
| [EGO-4](EGO-4.md) | Decentralized Exchange Standard | Final | Standards Track — Interface |
| [EGO-5](EGO-5.md) | Dynamic Fee Market | Final | Standards Track — Core |
| [EGO-6](EGO-6.md) | Light Client Protocol | Final | Standards Track — Networking |
| [EGO-7](EGO-7.md) | Account Abstraction | Final | Standards Track — Interface |
| [EGO-8](EGO-8.md) | On-Chain DAO Governance | Final | Standards Track — Interface |
| [EGO-9](EGO-9.md) | Oracle Standard | Final | Standards Track — Interface |
| [EGO-10](EGO-10.md) | Cross-Chain Bridge | Final | Standards Track — Interface |
| [EGO-11](EGO-11.md) | EGUSD Bridge-Backed Stablecoin | Final | Standards Track — Interface |
| [EGO-20](EGO-20.md) | Token Standard (Fungible) | Final | Standards Track — Interface |
| [EGO-15](EGO-15.md) | Government Services Standard | Final | Standards Track — Interface |
| [EGO-721](EGO-721.md) | Non-Fungible Token Standard | Final | Standards Track — Interface |

## How to Submit an EIP

1. Fork the `ego-blockchain` repository.
2. Copy `template.md` to `eips/EGO-XXXX.md` (use the next available number).
3. Fill in all required fields.
4. Open a Pull Request — the title must be `EGO-XXXX: <short title>`.
5. The EIP enters **Draft** status while community discussion happens.
6. The EIP authors address feedback in the PR comments.
7. Once there is rough consensus, a DAO vote is held (EGO-1 §6 for thresholds).
8. On approval, the PR is merged and the status is updated to **Final**.

## Status Flow

```
Draft → Review → Last Call (14 days) → Final
                              ↓
                           Withdrawn / Stagnant
```

## Categories

| Category | Description |
|----------|-------------|
| **Core** | Changes to consensus, block format, proof systems, or network protocol |
| **Interface** | Contract/ABI standards, token standards (like EGO-20) |
| **Networking** | P2P layer, GossipSub topics, discovery protocols |
| **Informational** | Design guidelines, best practices (non-normative) |
| **Process** | Changes to the EIP process itself |
