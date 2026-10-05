// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IERC20Balance {
    function balanceOf(address account) external view returns (uint256);
}

contract EgoEscrow {
    enum State {
        None,
        Funded,
        Released,
        Refunded
    }

    struct Escrow {
        address seller;
        uint64 openedAt;
        State state;
        bool frozen;
        address buyer;
        uint64 fallbackAt;
        address arbiter;
        address token;
        uint128 total;
        uint128 fee;
    }

    uint8 public constant ACTION_RELEASE = 1;
    uint8 public constant ACTION_CANCEL = 2;
    uint8 public constant ACTION_RESOLVE_BUYER = 3;
    uint8 public constant ACTION_RESOLVE_SELLER = 4;
    uint8 public constant ACTION_FREEZE = 5;

    uint64 public constant MIN_FALLBACK = 30 days;
    uint64 public constant MAX_FALLBACK = 365 days;
    uint256 public constant MAX_FEE_BPS = 1_000;
    string public constant VERSION = "1";

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ACTION_TYPEHASH = keccak256("Action(bytes32 key,uint8 action)");
    uint256 private constant HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable feeReceiver;
    uint256 private immutable cachedChainId;
    bytes32 private immutable cachedDomainSeparator;

    mapping(bytes32 => Escrow) public escrows;
    mapping(address => mapping(address => uint256)) public owed;

    uint256 private entered = 1;

    event Opened(
        bytes32 indexed key,
        bytes32 indexed tradeId,
        address indexed seller,
        address buyer,
        address arbiter,
        address token,
        uint256 total,
        uint256 fee,
        uint64 fallbackAt
    );
    event Released(bytes32 indexed key, address indexed by, uint256 toBuyer, uint256 fee);
    event Refunded(bytes32 indexed key, address indexed by, uint256 toSeller);
    event Frozen(bytes32 indexed key, address indexed by);
    event Owed(address indexed token, address indexed account, uint256 amount);
    event Withdrawn(address indexed token, address indexed account, uint256 amount);

    error UnknownEscrow();
    error NotFunded();
    error AlreadyUsed();
    error BadParty();
    error BadAmount();
    error BadFallback();
    error NotAllowed();
    error TooEarly();
    error BadSignature();
    error TransferFailed();
    error Reentrant();

    modifier nonReentrant() {
        if (entered != 1) revert Reentrant();
        entered = 2;
        _;
        entered = 1;
    }

    constructor(address feeReceiver_) {
        if (feeReceiver_ == address(0)) revert BadParty();
        feeReceiver = feeReceiver_;
        cachedChainId = block.chainid;
        cachedDomainSeparator = _buildDomainSeparator();
    }

    function keyOf(bytes32 tradeId, address seller) public pure returns (bytes32) {
        return keccak256(abi.encode(tradeId, seller));
    }

    function domainSeparator() public view returns (bytes32) {
        return block.chainid == cachedChainId ? cachedDomainSeparator : _buildDomainSeparator();
    }

    function actionDigest(bytes32 key, uint8 action) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(ACTION_TYPEHASH, key, action));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function open(
        bytes32 tradeId,
        address buyer,
        address arbiter,
        address token,
        uint128 total,
        uint128 fee,
        uint64 fallbackDelay
    ) external payable nonReentrant returns (bytes32 key) {
        if (buyer == address(0) || arbiter == address(0)) revert BadParty();
        if (buyer == msg.sender || arbiter == msg.sender || arbiter == buyer) revert BadParty();
        if (total == 0 || uint256(fee) * 10_000 > uint256(total) * MAX_FEE_BPS) revert BadAmount();
        if (fallbackDelay < MIN_FALLBACK || fallbackDelay > MAX_FALLBACK) revert BadFallback();
        key = keyOf(tradeId, msg.sender);
        if (escrows[key].state != State.None) revert AlreadyUsed();

        if (token == address(0)) {
            if (msg.value != total) revert BadAmount();
        } else {
            if (msg.value != 0) revert BadAmount();
            uint256 before = IERC20Balance(token).balanceOf(address(this));
            (bool ok, ) = token.call(abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), uint256(total)));
            if (!ok) revert TransferFailed();
            if (_received(token, before) != total) revert BadAmount();
        }

        uint64 nowTs = uint64(block.timestamp);
        escrows[key] = Escrow({
            seller: msg.sender,
            openedAt: nowTs,
            state: State.Funded,
            frozen: false,
            buyer: buyer,
            fallbackAt: nowTs + fallbackDelay,
            arbiter: arbiter,
            token: token,
            total: total,
            fee: fee
        });
        emit Opened(key, tradeId, msg.sender, buyer, arbiter, token, total, fee, nowTs + fallbackDelay);
    }

    function release(bytes32 key) external nonReentrant {
        Escrow storage e = _funded(key);
        if (msg.sender != e.seller) revert NotAllowed();
        _release(key, e, msg.sender);
    }

    function cancel(bytes32 key) external nonReentrant {
        Escrow storage e = _funded(key);
        if (msg.sender != e.buyer) revert NotAllowed();
        _refund(key, e, msg.sender);
    }

    function resolve(bytes32 key, bool toBuyer) external nonReentrant {
        Escrow storage e = _funded(key);
        if (msg.sender != e.arbiter) revert NotAllowed();
        if (toBuyer) {
            _release(key, e, msg.sender);
        } else {
            _refund(key, e, msg.sender);
        }
    }

    function freeze(bytes32 key) external nonReentrant {
        Escrow storage e = _funded(key);
        if (msg.sender != e.buyer && msg.sender != e.arbiter) revert NotAllowed();
        _freeze(key, e, msg.sender);
    }

    function reclaim(bytes32 key) external nonReentrant {
        Escrow storage e = _funded(key);
        if (msg.sender != e.seller) revert NotAllowed();
        if (e.frozen) revert NotAllowed();
        if (block.timestamp < e.fallbackAt) revert TooEarly();
        _refund(key, e, msg.sender);
    }

    function releaseFor(bytes32 key, bytes calldata sig) external nonReentrant {
        Escrow storage e = _funded(key);
        _requireSigner(key, ACTION_RELEASE, sig, e.seller);
        _release(key, e, e.seller);
    }

    function cancelFor(bytes32 key, bytes calldata sig) external nonReentrant {
        Escrow storage e = _funded(key);
        _requireSigner(key, ACTION_CANCEL, sig, e.buyer);
        _refund(key, e, e.buyer);
    }

    function resolveFor(bytes32 key, bool toBuyer, bytes calldata sig) external nonReentrant {
        Escrow storage e = _funded(key);
        _requireSigner(key, toBuyer ? ACTION_RESOLVE_BUYER : ACTION_RESOLVE_SELLER, sig, e.arbiter);
        if (toBuyer) {
            _release(key, e, e.arbiter);
        } else {
            _refund(key, e, e.arbiter);
        }
    }

    function freezeFor(bytes32 key, bytes calldata sig) external nonReentrant {
        Escrow storage e = _funded(key);
        _requireSigner(key, ACTION_FREEZE, sig, e.buyer);
        _freeze(key, e, e.buyer);
    }

    function withdraw(address token) external nonReentrant {
        uint256 amount = owed[token][msg.sender];
        if (amount == 0) revert BadAmount();
        owed[token][msg.sender] = 0;
        if (!_send(token, msg.sender, amount)) revert TransferFailed();
        emit Withdrawn(token, msg.sender, amount);
    }

    function _funded(bytes32 key) private view returns (Escrow storage e) {
        e = escrows[key];
        if (e.state == State.None) revert UnknownEscrow();
        if (e.state != State.Funded) revert NotFunded();
    }

    function _release(bytes32 key, Escrow storage e, address by) private {
        e.state = State.Released;
        uint256 fee = e.fee;
        uint256 toBuyer = uint256(e.total) - fee;
        _pay(e.token, e.buyer, toBuyer);
        if (fee > 0) {
            _pay(e.token, feeReceiver, fee);
        }
        emit Released(key, by, toBuyer, fee);
    }

    function _refund(bytes32 key, Escrow storage e, address by) private {
        e.state = State.Refunded;
        uint256 amount = e.total;
        _pay(e.token, e.seller, amount);
        emit Refunded(key, by, amount);
    }

    function _freeze(bytes32 key, Escrow storage e, address by) private {
        if (e.frozen) revert NotAllowed();
        e.frozen = true;
        emit Frozen(key, by);
    }

    function _pay(address token, address to, uint256 amount) private {
        if (!_send(token, to, amount)) {
            owed[token][to] += amount;
            emit Owed(token, to, amount);
        }
    }

    function _send(address token, address to, uint256 amount) private returns (bool) {
        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount, gas: 30_000}("");
            return ok;
        }
        uint256 before = IERC20Balance(token).balanceOf(address(this));
        (bool called, ) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        uint256 afterBalance = IERC20Balance(token).balanceOf(address(this));
        if (afterBalance == before) {
            return false;
        }
        if (!called || afterBalance > before || before - afterBalance != amount) revert TransferFailed();
        return true;
    }

    function _received(address token, uint256 before) private view returns (uint256) {
        uint256 afterBalance = IERC20Balance(token).balanceOf(address(this));
        return afterBalance > before ? afterBalance - before : 0;
    }

    function _requireSigner(bytes32 key, uint8 action, bytes calldata sig, address expected) private view {
        if (sig.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert BadSignature();
        if (uint256(s) > HALF_ORDER) revert BadSignature();
        address signer = ecrecover(actionDigest(key, action), v, r, s);
        if (signer == address(0) || signer != expected) revert BadSignature();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("EgoEscrow"), keccak256(bytes(VERSION)), block.chainid, address(this))
        );
    }
}
