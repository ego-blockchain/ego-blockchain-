# Ego Wallet for iPhone

Ego Wallet for iPhone holds EGOC, shows live Ego storage capacity, joins the Governance community chat and browses the P2P market. Keys never leave the phone. Every transaction and chat message is signed on the device.

## What's here

| Path | What it is |
| --- | --- |
| `EgoKit/` | Swift package with keys, addresses, the 24-word phrase, transaction and chat signing, gateway discovery and market models. It is byte-compatible with Ego Desktop and the browser extension. |
| `EgoWallet/` | The SwiftUI app, with five tabs: Wallet, Storage, Chat, Market and Settings. |
| `project.yml` | XcodeGen spec that generates the Xcode project. |

## Build on a Mac

1. Install Xcode 15.3 or newer (iOS 17 SDK), then XcodeGen: `brew install xcodegen`.
2. `cd ios && xcodegen generate`
3. `open EgoWallet.xcodeproj`, choose your team under Signing & Capabilities, and run it on a device or simulator.
4. `cd EgoKit && swift test` runs the shared tests. All 26 pass.

The wallet keeps its seed in the Keychain behind Face ID or the passcode. The iPhone needs a passcode set.

## Getting phones online

Phones talk to the network through Ego Desktop computers that choose to serve them:

1. In Ego Desktop, open Settings and turn on **Serve phones**.
2. Forward TCP port 47398 on the router to that computer. The settings card shows when a phone or another gateway has reached it from the internet.
3. Redeploy the oracle with the `/gateways` routes. A brand-new phone uses this list only once, to find its first gateway.

## Why millions of phones don't overload the oracle

- **The oracle is only a phone book for first contact.** It checks a signature and serves one cached list that CDNs may cache for 5 minutes. It never probes anything.
- **Phones keep up to 200 gateways.** They learn more from the gateways themselves (`gateway.list`), so after the first contact they stop asking the oracle.
- **Phones ask the oracle only when no saved gateway answers.** After that the gap starts at 10 minutes and doubles up to 6 hours. A phone that has never connected starts at 30 seconds and backs off to 10 minutes.
- **A gateway that fails cools down instead of being forgotten.** The pause starts at 1 minute and doubles to 6 hours. When the phone switches networks, all pauses reset.
- **Saved gateways are tried in waves of 3, up to 9 per attempt.** The first one to answer wins.
- **Offline phones make no requests at all.**

## Not built yet

- **Uploading files from the phone.** The Storage tab already shows live free space and how many computers provide it.
- **Trading from the phone.** The Market tab lists live offers with prices, limits, methods and trader records. Trades still open in Ego Desktop.
- **Proof of what a gateway says.** A dishonest gateway can't move anyone's coins, because everything is signed on the phone. It could still show a wrong balance or hide chat posts. The next step is to cross-check two gateways or verify chain proofs.
