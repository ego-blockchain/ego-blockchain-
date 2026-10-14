# Contracts

## Urego library (`*.urego`): design drafts, not deployable

The `.urego` files under `accounts/`, `bridge/`, `defi/`, `dex/`, `governance/`, `government/`, `launchpad/`, `lending/`, `nft/`, `oracle/`, `stable/` and `utils/` are drafts written against Urego features that the compiler does not support yet: `event` and `const` declarations, `u128` values, `require`, free functions outside a `contract` block, and statements without trailing semicolons.

None of them compile with the current `crates/urego-compiler`. Do not deploy them, and do not treat them as audited code. They will be ported as the language gains these features, and each one will get a compile test when it is.

What compiles and runs today:

- the templates in the dApp IDE (`ego-desktop/src-frontend/pages/IDEPage.tsx`): Hello World, Token, Escrow, DAO and Guestbook
- the examples in `crates/urego-compiler/src/lib.rs` tests

The current language: one `contract` block of `fn` / `pub fn` items, `u64` arithmetic, `let`, `if` / `else`, `for i in a..b`, `assert`, `storage.get_u64` / `storage.set`, and `events.emit`. Arithmetic is checked: an add, subtract or multiply that overflows aborts the call, and nothing it wrote is kept.

## Escrow contracts for the P2P market

`p2p/` (Solidity, Hardhat), `p2p-solana/` and `p2p-cardano/` (Aiken) are the escrow contracts the P2P market uses on other chains. They are built and tested with their own toolchains and are separate from the Urego drafts above.
