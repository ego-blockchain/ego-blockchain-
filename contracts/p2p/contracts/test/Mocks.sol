// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract MockToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        _spend(from, amount);
        _move(from, to, amount);
        return true;
    }

    function _spend(address from, uint256 amount) internal {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
    }

    function _move(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract MockUSDT {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted;
    uint8 public constant decimals = 6;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setBlacklisted(address who, bool on) external {
        blacklisted[who] = on;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) private {
        require(!blacklisted[from] && !blacklisted[to], "blacklisted");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract FalseReturningToken is MockToken {
    constructor() MockToken("False", "FLS", 6) {}

    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, amount);
        return false;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        _spend(from, amount);
        _move(from, to, amount);
        return false;
    }
}

contract SilentFailToken is MockToken {
    constructor() MockToken("Silent", "SIL", 6) {}

    function transfer(address, uint256) external pure override returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) external pure override returns (bool) {
        return false;
    }
}

contract FeeOnTransferToken is MockToken {
    constructor() MockToken("Fee", "FEE", 18) {}

    function _move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "balance");
        uint256 cut = amount / 100;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - cut;
    }
}

contract ToggleFeeToken is MockToken {
    bool public skim;

    constructor() MockToken("Toggle", "TGL", 6) {}

    function setSkim(bool on) external {
        skim = on;
    }

    function _move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "balance");
        uint256 cut = skim ? amount / 100 : 0;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - cut;
        balanceOf[address(0xdead)] += cut;
    }
}

interface IEscrowLike {
    function release(bytes32 key) external;
    function cancel(bytes32 key) external;
    function withdraw(address token) external;
}

contract HostileReceiver {
    IEscrowLike public escrow;
    bytes32 public key;
    bool public refuse;
    bool public attack;

    function arm(address escrow_, bytes32 key_, bool refuse_, bool attack_) external {
        escrow = IEscrowLike(escrow_);
        key = key_;
        refuse = refuse_;
        attack = attack_;
    }

    function pull(address token) external {
        escrow.withdraw(token);
    }

    receive() external payable {
        if (attack) {
            escrow.cancel(key);
        }
        require(!refuse, "refused");
    }
}
