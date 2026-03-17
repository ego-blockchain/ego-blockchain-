# Ego Governance

Standalone single-page DAO governance app for the Ego Blockchain testnet.

## Usage

Open `index.html` directly in any modern browser — no build step required.

## Features

- **Proposals list** with live vote bars, quorum progress, and status badges
- **Vote Yes / Vote No** (calls `window.ego.request({ method: 'ego_vote', params: [id, support] })`)
- **Create Proposal** form with title, description, voting period, and optional on-chain calldata
- **My Votes** tab showing your voting history for the session
- **Stats bar**: total proposals, participation rate, voting power, quorum threshold
- **Wallet connect** via `window.ego` provider or demo mode (fake wallet)

## RPC

Connects to `http://127.0.0.1:8545` for balance queries.
Override by editing the `RPC` constant at the top of the `<script>` block.

## Spec

Governance logic follows **EGO-52** (on-chain governance framework).
