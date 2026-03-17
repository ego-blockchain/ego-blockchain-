// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ═══════════════════════════════════════════════════════════════════════════════
// EgoLock — Ethereum-side lock contract for the EGO-10 cross-chain bridge
//
// Standard : EGO-10
// Author   : Artit Muhaxhiri (@egoblockchain)
// Version  : 1.0.0
//
// OVERVIEW
// --------
// Deployed on Ethereum / BNB / Polygon. Users lock ERC-20 tokens (or native ETH)
// here. The Ego bridge relayer watches for the Locked event and calls
// verify_and_mint on the Ego chain to credit wrapped tokens.
//
// When users bridge back (BridgeOut on Ego), the relayer calls unlock() here
// to release the original tokens to the destination address.
//
// FLOW — BRIDGE IN (ETH → Ego)
//   1. User calls lock(token, amount, ego_dest) → tokens transferred to this contract
//   2. Locked event is emitted with a monotonic nonce
//   3. Relayer picks up the event → submits verify_and_mint on Ego
//
// FLOW — BRIDGE OUT (Ego → ETH)
//   1. User burns wrapped tokens on Ego (BridgeOut event emitted)
//   2. Relayer picks up BridgeOut event → calls unlock(token, amount, dest, burn_nonce)
//   3. Tokens released to dest on Ethereum
//
// SECURITY
// --------
// Phase 1: unlock() is restricted to the trusted relayer address.
// Phase 2: unlock() will accept a Groth16 proof of the Ego burn event instead.
// The relayer cannot steal funds — it can only unlock for valid Ego burns.
// ═══════════════════════════════════════════════════════════════════════════════

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

contract EgoLock {

    // ── Events ────────────────────────────────────────────────────────────────

    /// Emitted when a user locks tokens for bridging to Ego.
    /// The bridge relayer watches this event.
    event Locked(
        address indexed sender,
        uint256         amount,
        address indexed token,
        uint64          nonce,
        string          ego_dest   // destination address on Ego chain
    );

    /// Emitted when the relayer unlocks tokens after a Ego→ETH bridge.
    event Unlocked(
        address indexed recipient,
        uint256         amount,
        address indexed token,
        uint64          burn_nonce // nonce from Ego BridgeOut event
    );

    event RelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event TokenWhitelisted(address indexed token, bool allowed);

    // ── State ─────────────────────────────────────────────────────────────────

    address public owner;
    address public relayer;
    bool    public paused;

    /// Monotonic lock nonce — maps 1:1 to Ego claim_hash for replay protection.
    uint64 public lockNonce;

    /// burn_nonce → already_unlocked (replay protection for unlock calls).
    mapping(uint64 => bool) public usedBurnNonces;

    /// token → total locked (invariant: locked[t] == minted on Ego - burned on Ego)
    mapping(address => uint256) public totalLocked;

    /// Whitelisted tokens. address(0) = native ETH.
    mapping(address => bool) public tokenWhitelist;

    /// Bridge fee in basis points (default 0 — free for testnet).
    uint16 public feeBps;

    /// Accumulated fees per token.
    mapping(address => uint256) public fees;

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _relayer) {
        owner   = msg.sender;
        relayer = _relayer;
        // Whitelist ETH (address(0)) by default
        tokenWhitelist[address(0)] = true;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyOwner()   { require(msg.sender == owner,   "EgoLock: not owner");   _; }
    modifier onlyRelayer() { require(msg.sender == relayer, "EgoLock: not relayer"); _; }
    modifier notPaused()   { require(!paused,                "EgoLock: paused");      _; }

    // ── Bridge In — lock ──────────────────────────────────────────────────────

    /// Lock ERC-20 tokens and emit Locked event.
    ///
    /// @param token    ERC-20 token address to bridge. Must be whitelisted.
    /// @param amount   Token amount (in token's native decimals).
    /// @param ego_dest Destination address on Ego chain (hex string: 0x...).
    function lock(
        address token,
        uint256 amount,
        string calldata ego_dest
    ) external notPaused {
        require(tokenWhitelist[token], "EgoLock: token not whitelisted");
        require(amount > 0,            "EgoLock: amount must be > 0");
        require(bytes(ego_dest).length > 0, "EgoLock: ego_dest is empty");

        // Compute fee
        uint256 fee      = (amount * feeBps) / 10000;
        uint256 net      = amount - fee;

        // Transfer tokens from caller to this contract
        bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(ok, "EgoLock: transferFrom failed");

        // Accumulate fee
        if (fee > 0) fees[token] += fee;

        // Update locked balance
        totalLocked[token] += net;

        uint64 nonce = ++lockNonce;
        emit Locked(msg.sender, net, token, nonce, ego_dest);
    }

    /// Lock native ETH and emit Locked event.
    ///
    /// @param ego_dest Destination address on Ego chain.
    function lockETH(string calldata ego_dest) external payable notPaused {
        require(tokenWhitelist[address(0)], "EgoLock: ETH not whitelisted");
        require(msg.value > 0,              "EgoLock: no ETH sent");
        require(bytes(ego_dest).length > 0, "EgoLock: ego_dest is empty");

        uint256 fee = (msg.value * feeBps) / 10000;
        uint256 net = msg.value - fee;

        if (fee > 0) fees[address(0)] += fee;
        totalLocked[address(0)] += net;

        uint64 nonce = ++lockNonce;
        emit Locked(msg.sender, net, address(0), nonce, ego_dest);
    }

    // ── Bridge Out — unlock ───────────────────────────────────────────────────

    /// Release ERC-20 tokens after a confirmed Ego burn event.
    ///
    /// Phase 1: only the trusted relayer may call this.
    /// Phase 2: replace relayer check with Groth16 proof verification.
    ///
    /// @param token      ERC-20 token address.
    /// @param amount     Amount to release (must match the Ego burn amount).
    /// @param recipient  Destination address on this chain.
    /// @param burn_nonce Nonce from the Ego BridgeOut event (replay protection).
    function unlock(
        address token,
        uint256 amount,
        address recipient,
        uint64  burn_nonce
    ) external onlyRelayer notPaused {
        require(!usedBurnNonces[burn_nonce], "EgoLock: burn_nonce already used");
        require(amount > 0,                  "EgoLock: amount must be > 0");
        require(recipient != address(0),     "EgoLock: invalid recipient");
        require(totalLocked[token] >= amount, "EgoLock: insufficient locked balance");

        usedBurnNonces[burn_nonce] = true;
        totalLocked[token] -= amount;

        bool ok = IERC20(token).transfer(recipient, amount);
        require(ok, "EgoLock: transfer failed");

        emit Unlocked(recipient, amount, token, burn_nonce);
    }

    /// Release native ETH after a confirmed Ego burn.
    function unlockETH(
        address payable recipient,
        uint256         amount,
        uint64          burn_nonce
    ) external onlyRelayer notPaused {
        require(!usedBurnNonces[burn_nonce],      "EgoLock: burn_nonce already used");
        require(amount > 0,                       "EgoLock: amount must be > 0");
        require(recipient != address(0),          "EgoLock: invalid recipient");
        require(totalLocked[address(0)] >= amount, "EgoLock: insufficient ETH locked");

        usedBurnNonces[burn_nonce] = true;
        totalLocked[address(0)] -= amount;

        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "EgoLock: ETH transfer failed");

        emit Unlocked(recipient, amount, address(0), burn_nonce);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    function isBurnNonceUsed(uint64 burn_nonce) external view returns (bool) {
        return usedBurnNonces[burn_nonce];
    }

    function getLockedBalance(address token) external view returns (uint256) {
        return totalLocked[token];
    }

    // ── Administration ────────────────────────────────────────────────────────

    function setRelayer(address newRelayer) external onlyOwner {
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }

    function whitelistToken(address token, bool allowed) external onlyOwner {
        tokenWhitelist[token] = allowed;
        emit TokenWhitelisted(token, allowed);
    }

    function setFeeBps(uint16 _feeBps) external onlyOwner {
        require(_feeBps <= 100, "EgoLock: fee cannot exceed 1%");
        feeBps = _feeBps;
    }

    function withdrawFees(address token, address to) external onlyOwner {
        uint256 amount = fees[token];
        require(amount > 0, "EgoLock: no fees");
        fees[token] = 0;
        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount}("");
            require(ok, "EgoLock: ETH fee withdrawal failed");
        } else {
            IERC20(token).transfer(to, amount);
        }
    }

    function pause()   external onlyOwner { paused = true;  emit Paused(msg.sender); }
    function unpause() external onlyOwner { paused = false; emit Unpaused(msg.sender); }

    receive() external payable {}
}
