const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

const DAY = 24 * 60 * 60;
const FALLBACK = 30 * DAY;
const ACTION = { release: 1, cancel: 2, resolveBuyer: 3, resolveSeller: 4, freeze: 5 };
const tradeId = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

async function deploy() {
  const [deployer, seller, buyer, arbiter, treasury, stranger] = await ethers.getSigners();
  const escrow = await (await ethers.getContractFactory("EgoEscrow")).deploy(treasury.address);
  const usdc = await (await ethers.getContractFactory("MockToken")).deploy("USD Coin", "USDC", 6);
  const usdt = await (await ethers.getContractFactory("MockUSDT")).deploy();
  for (const t of [usdc, usdt]) {
    await t.mint(seller.address, 1_000_000_000_000n);
  }
  return { escrow, usdc, usdt, deployer, seller, buyer, arbiter, treasury, stranger };
}

async function sign(signer, escrow, key, action) {
  const net = await ethers.provider.getNetwork();
  return signer.signTypedData(
    { name: "EgoEscrow", version: "1", chainId: net.chainId, verifyingContract: await escrow.getAddress() },
    { Action: [{ name: "key", type: "bytes32" }, { name: "action", type: "uint8" }] },
    { key, action },
  );
}

async function openNative(ctx, n = 1, total = ethers.parseEther("1"), fee = ethers.parseEther("0.01")) {
  const { escrow, seller, buyer, arbiter } = ctx;
  await escrow.connect(seller).open(tradeId(n), buyer.address, arbiter.address, ethers.ZeroAddress, total, fee, FALLBACK, { value: total });
  return escrow.keyOf(tradeId(n), seller.address);
}

async function openToken(ctx, token, n = 1, total = 100_000_000n, fee = 1_000_000n) {
  const { escrow, seller, buyer, arbiter } = ctx;
  await token.connect(seller).approve(await escrow.getAddress(), total);
  await escrow.connect(seller).open(tradeId(n), buyer.address, arbiter.address, await token.getAddress(), total, fee, FALLBACK);
  return escrow.keyOf(tradeId(n), seller.address);
}

describe("EgoEscrow", function () {
  describe("opening", function () {
    it("locks a native deposit and records every term", async function () {
      const ctx = await deploy();
      const { escrow, seller, buyer, arbiter } = ctx;
      const total = ethers.parseEther("2");
      const tx = escrow.connect(seller).open(tradeId(7), buyer.address, arbiter.address, ethers.ZeroAddress, total, total / 100n, FALLBACK, { value: total });
      const key = await escrow.keyOf(tradeId(7), seller.address);
      await expect(tx).to.emit(escrow, "Opened");
      const e = await escrow.escrows(key);
      expect(e.seller).to.equal(seller.address);
      expect(e.buyer).to.equal(buyer.address);
      expect(e.arbiter).to.equal(arbiter.address);
      expect(e.token).to.equal(ethers.ZeroAddress);
      expect(e.total).to.equal(total);
      expect(e.fee).to.equal(total / 100n);
      expect(e.state).to.equal(1);
      expect(e.frozen).to.equal(false);
      expect(e.fallbackAt - e.openedAt).to.equal(BigInt(FALLBACK));
      expect(await ethers.provider.getBalance(await escrow.getAddress())).to.equal(total);
    });

    it("pulls tokens and refuses anything but the exact amount", async function () {
      const ctx = await deploy();
      const key = await openToken(ctx, ctx.usdc);
      expect(await ctx.usdc.balanceOf(await ctx.escrow.getAddress())).to.equal(100_000_000n);
      expect((await ctx.escrow.escrows(key)).state).to.equal(1);
    });

    it("refuses bad parties, amounts, fallbacks and reuse", async function () {
      const ctx = await deploy();
      const { escrow, seller, buyer, arbiter } = ctx;
      const z = ethers.ZeroAddress;
      const v = { value: 1000n };
      const open = (b, a, total, fee, fb, opts = v) => escrow.connect(seller).open(tradeId(1), b, a, z, total, fee, fb, opts);
      await expect(open(z, arbiter.address, 1000n, 10n, FALLBACK)).to.be.revertedWithCustomError(escrow, "BadParty");
      await expect(open(seller.address, arbiter.address, 1000n, 10n, FALLBACK)).to.be.revertedWithCustomError(escrow, "BadParty");
      await expect(open(buyer.address, seller.address, 1000n, 10n, FALLBACK)).to.be.revertedWithCustomError(escrow, "BadParty");
      await expect(open(buyer.address, buyer.address, 1000n, 10n, FALLBACK)).to.be.revertedWithCustomError(escrow, "BadParty");
      await expect(open(buyer.address, arbiter.address, 0n, 0n, FALLBACK, { value: 0n })).to.be.revertedWithCustomError(escrow, "BadAmount");
      await expect(open(buyer.address, arbiter.address, 1000n, 101n, FALLBACK)).to.be.revertedWithCustomError(escrow, "BadAmount");
      await expect(open(buyer.address, arbiter.address, 1000n, 10n, FALLBACK - 1)).to.be.revertedWithCustomError(escrow, "BadFallback");
      await expect(open(buyer.address, arbiter.address, 1000n, 10n, 366 * DAY)).to.be.revertedWithCustomError(escrow, "BadFallback");
      await expect(open(buyer.address, arbiter.address, 1000n, 10n, FALLBACK, { value: 999n })).to.be.revertedWithCustomError(escrow, "BadAmount");
      await open(buyer.address, arbiter.address, 1000n, 100n, FALLBACK);
      await expect(open(buyer.address, arbiter.address, 1000n, 10n, FALLBACK)).to.be.revertedWithCustomError(escrow, "AlreadyUsed");
      await expect(
        escrow.connect(seller).open(tradeId(2), buyer.address, arbiter.address, await ctx.usdc.getAddress(), 10n, 0n, FALLBACK, { value: 10n }),
      ).to.be.revertedWithCustomError(escrow, "BadAmount");
    });

    it("scopes the key to the seller, so nobody can squat a trade id", async function () {
      const ctx = await deploy();
      const { escrow, stranger, buyer, arbiter, seller } = ctx;
      await escrow.connect(stranger).open(tradeId(9), buyer.address, arbiter.address, ethers.ZeroAddress, 5n, 0n, FALLBACK, { value: 5n });
      const key = await openNative(ctx, 9);
      expect((await escrow.escrows(key)).seller).to.equal(seller.address);
      expect(key).to.not.equal(await escrow.keyOf(tradeId(9), stranger.address));
    });

    it("refuses a token that keeps a cut of every transfer", async function () {
      const ctx = await deploy();
      const fot = await (await ethers.getContractFactory("FeeOnTransferToken")).deploy();
      await fot.mint(ctx.seller.address, 1_000_000n);
      await fot.connect(ctx.seller).approve(await ctx.escrow.getAddress(), 1_000_000n);
      await expect(
        ctx.escrow.connect(ctx.seller).open(tradeId(1), ctx.buyer.address, ctx.arbiter.address, await fot.getAddress(), 1_000_000n, 0n, FALLBACK),
      ).to.be.revertedWithCustomError(ctx.escrow, "BadAmount");
    });

    it("refuses a token that says no and moves nothing", async function () {
      const ctx = await deploy();
      const silent = await (await ethers.getContractFactory("SilentFailToken")).deploy();
      await silent.mint(ctx.seller.address, 1_000n);
      await silent.connect(ctx.seller).approve(await ctx.escrow.getAddress(), 1_000n);
      await expect(
        ctx.escrow.connect(ctx.seller).open(tradeId(1), ctx.buyer.address, ctx.arbiter.address, await silent.getAddress(), 1_000n, 0n, FALLBACK),
      ).to.be.revertedWithCustomError(ctx.escrow, "BadAmount");
    });
  });

  describe("settling", function () {
    it("the seller releases: the buyer gets total minus fee and the treasury the fee", async function () {
      const ctx = await deploy();
      const key = await openToken(ctx, ctx.usdc);
      await expect(ctx.escrow.connect(ctx.seller).release(key))
        .to.emit(ctx.escrow, "Released")
        .withArgs(key, ctx.seller.address, 99_000_000n, 1_000_000n);
      expect(await ctx.usdc.balanceOf(ctx.buyer.address)).to.equal(99_000_000n);
      expect(await ctx.usdc.balanceOf(ctx.treasury.address)).to.equal(1_000_000n);
      expect(await ctx.usdc.balanceOf(await ctx.escrow.getAddress())).to.equal(0n);
      await expect(ctx.escrow.connect(ctx.seller).release(key)).to.be.revertedWithCustomError(ctx.escrow, "NotFunded");
      await expect(ctx.escrow.connect(ctx.buyer).cancel(key)).to.be.revertedWithCustomError(ctx.escrow, "NotFunded");
    });

    it("only the right party can move the money", async function () {
      const ctx = await deploy();
      const key = await openNative(ctx);
      const { escrow, seller, buyer, arbiter, stranger } = ctx;
      await expect(escrow.connect(buyer).release(key)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(arbiter).release(key)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(seller).cancel(key)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(stranger).resolve(key, true)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(seller).resolve(key, false)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(stranger).freeze(key)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(seller).freeze(key)).to.be.revertedWithCustomError(escrow, "NotAllowed");
      await expect(escrow.connect(stranger).release(ethers.ZeroHash)).to.be.revertedWithCustomError(escrow, "UnknownEscrow");
    });

    it("the buyer cancels: the seller gets everything back, fee included", async function () {
      const ctx = await deploy();
      const key = await openNative(ctx);
      const before = await ethers.provider.getBalance(ctx.seller.address);
      const treasury = await ethers.provider.getBalance(ctx.treasury.address);
      await expect(ctx.escrow.connect(ctx.buyer).cancel(key)).to.emit(ctx.escrow, "Refunded").withArgs(key, ctx.buyer.address, ethers.parseEther("1"));
      expect(await ethers.provider.getBalance(ctx.seller.address)).to.equal(before + ethers.parseEther("1"));
      expect(await ethers.provider.getBalance(ctx.treasury.address)).to.equal(treasury);
    });

    it("the arbiter can rule either way, once", async function () {
      const ctx = await deploy();
      const a = await openToken(ctx, ctx.usdc, 1);
      const b = await openToken(ctx, ctx.usdc, 2);
      await ctx.escrow.connect(ctx.arbiter).resolve(a, true);
      await ctx.escrow.connect(ctx.arbiter).resolve(b, false);
      expect(await ctx.usdc.balanceOf(ctx.buyer.address)).to.equal(99_000_000n);
      expect(await ctx.usdc.balanceOf(ctx.seller.address)).to.equal(1_000_000_000_000n - 100_000_000n);
      await expect(ctx.escrow.connect(ctx.arbiter).resolve(a, false)).to.be.revertedWithCustomError(ctx.escrow, "NotFunded");
    });

    it("the seller can only reclaim after the long fallback, and not once frozen", async function () {
      const ctx = await deploy();
      const a = await openNative(ctx, 1);
      const b = await openNative(ctx, 2);
      await expect(ctx.escrow.connect(ctx.seller).reclaim(a)).to.be.revertedWithCustomError(ctx.escrow, "TooEarly");
      await ctx.escrow.connect(ctx.buyer).freeze(b);
      await expect(ctx.escrow.connect(ctx.buyer).freeze(b)).to.be.revertedWithCustomError(ctx.escrow, "NotAllowed");
      await time.increase(FALLBACK);
      await expect(ctx.escrow.connect(ctx.buyer).reclaim(a)).to.be.revertedWithCustomError(ctx.escrow, "NotAllowed");
      await ctx.escrow.connect(ctx.seller).reclaim(a);
      expect((await ctx.escrow.escrows(a)).state).to.equal(3);
      await expect(ctx.escrow.connect(ctx.seller).reclaim(b)).to.be.revertedWithCustomError(ctx.escrow, "NotAllowed");
      await ctx.escrow.connect(ctx.seller).release(b);
      expect((await ctx.escrow.escrows(b)).state).to.equal(2);
    });
  });

  describe("signatures", function () {
    it("the digest is standard EIP-712, so any wallet can sign it", async function () {
      const ctx = await deploy();
      const key = await openNative(ctx);
      const net = await ethers.provider.getNetwork();
      const expected = ethers.TypedDataEncoder.hash(
        { name: "EgoEscrow", version: "1", chainId: net.chainId, verifyingContract: await ctx.escrow.getAddress() },
        { Action: [{ name: "key", type: "bytes32" }, { name: "action", type: "uint8" }] },
        { key, action: ACTION.release },
      );
      expect(await ctx.escrow.actionDigest(key, ACTION.release)).to.equal(expected);
    });

    it("anyone can relay a party's signed decision, so the buyer needs no gas", async function () {
      const ctx = await deploy();
      const { escrow, seller, buyer, arbiter, stranger } = ctx;
      const a = await openToken(ctx, ctx.usdc, 1);
      await escrow.connect(stranger).releaseFor(a, await sign(seller, escrow, a, ACTION.release));
      expect(await ctx.usdc.balanceOf(buyer.address)).to.equal(99_000_000n);

      const b = await openToken(ctx, ctx.usdc, 2);
      await escrow.connect(seller).cancelFor(b, await sign(buyer, escrow, b, ACTION.cancel));
      expect((await escrow.escrows(b)).state).to.equal(3);

      const c = await openToken(ctx, ctx.usdc, 3);
      await escrow.connect(buyer).resolveFor(c, true, await sign(arbiter, escrow, c, ACTION.resolveBuyer));
      expect((await escrow.escrows(c)).state).to.equal(2);

      const d = await openToken(ctx, ctx.usdc, 4);
      await escrow.connect(seller).freezeFor(d, await sign(buyer, escrow, d, ACTION.freeze));
      expect((await escrow.escrows(d)).frozen).to.equal(true);
    });

    it("a signature only works for its signer, its action and its escrow", async function () {
      const ctx = await deploy();
      const { escrow, seller, buyer, arbiter, stranger } = ctx;
      const a = await openToken(ctx, ctx.usdc, 1);
      const b = await openToken(ctx, ctx.usdc, 2);
      await expect(escrow.releaseFor(a, await sign(buyer, escrow, a, ACTION.release))).to.be.revertedWithCustomError(escrow, "BadSignature");
      await expect(escrow.releaseFor(a, await sign(seller, escrow, a, ACTION.cancel))).to.be.revertedWithCustomError(escrow, "BadSignature");
      await expect(escrow.releaseFor(a, await sign(seller, escrow, b, ACTION.release))).to.be.revertedWithCustomError(escrow, "BadSignature");
      await expect(escrow.resolveFor(a, false, await sign(arbiter, escrow, a, ACTION.resolveBuyer))).to.be.revertedWithCustomError(escrow, "BadSignature");
      await expect(escrow.cancelFor(a, "0x1234")).to.be.revertedWithCustomError(escrow, "BadSignature");

      const sig = await sign(seller, escrow, a, ACTION.release);
      await escrow.connect(stranger).releaseFor(a, sig);
      await expect(escrow.connect(stranger).releaseFor(a, sig)).to.be.revertedWithCustomError(escrow, "NotFunded");
    });

    it("the arbiter can sign a refund for someone else to submit", async function () {
      const ctx = await deploy();
      const key = await openToken(ctx, ctx.usdc);
      await expect(ctx.escrow.connect(ctx.seller).resolveFor(key, false, await sign(ctx.arbiter, ctx.escrow, key, ACTION.resolveSeller)))
        .to.emit(ctx.escrow, "Refunded")
        .withArgs(key, ctx.arbiter.address, 100_000_000n);
      expect(await ctx.usdc.balanceOf(ctx.seller.address)).to.equal(1_000_000_000_000n);
    });

    it("accepts a recovery id written as 0 or 1", async function () {
      const ctx = await deploy();
      const key = await openNative(ctx);
      const sig = ethers.Signature.from(await sign(ctx.seller, ctx.escrow, key, ACTION.release));
      const low = ethers.concat([sig.r, sig.s, ethers.toBeHex(sig.v - 27, 1)]);
      await ctx.escrow.releaseFor(key, low);
      expect((await ctx.escrow.escrows(key)).state).to.equal(2);
    });

    it("refuses the malleable twin of a valid signature", async function () {
      const ctx = await deploy();
      const key = await openNative(ctx);
      const sig = ethers.Signature.from(await sign(ctx.seller, ctx.escrow, key, ACTION.release));
      const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const highS = ethers.toBeHex(n - BigInt(sig.s), 32);
      const twin = ethers.concat([sig.r, highS, ethers.toBeHex(sig.v === 27 ? 28 : 27, 1)]);
      await expect(ctx.escrow.releaseFor(key, twin)).to.be.revertedWithCustomError(ctx.escrow, "BadSignature");
      await ctx.escrow.releaseFor(key, sig.serialized);
    });
  });

  describe("awkward tokens", function () {
    it("works with USDT, which returns nothing from transfer", async function () {
      const ctx = await deploy();
      const key = await openToken(ctx, ctx.usdt);
      await ctx.escrow.connect(ctx.seller).release(key);
      expect(await ctx.usdt.balanceOf(ctx.buyer.address)).to.equal(99_000_000n);
      expect(await ctx.usdt.balanceOf(ctx.treasury.address)).to.equal(1_000_000n);
    });

    it("works with a token that returns false but moves the money", async function () {
      const ctx = await deploy();
      const t = await (await ethers.getContractFactory("FalseReturningToken")).deploy();
      await t.mint(ctx.seller.address, 1_000_000_000n);
      const key = await openToken(ctx, t);
      await ctx.escrow.connect(ctx.buyer).cancel(key);
      expect(await t.balanceOf(ctx.seller.address)).to.equal(1_000_000_000n);
    });

    it("a blacklisted buyer's payout waits as a claim instead of freezing the escrow", async function () {
      const ctx = await deploy();
      const { escrow, usdt, seller, buyer, treasury } = ctx;
      const key = await openToken(ctx, usdt);
      await usdt.setBlacklisted(buyer.address, true);
      await expect(escrow.connect(seller).release(key)).to.emit(escrow, "Owed").withArgs(await usdt.getAddress(), buyer.address, 99_000_000n);
      expect((await escrow.escrows(key)).state).to.equal(2);
      expect(await usdt.balanceOf(treasury.address)).to.equal(1_000_000n);
      expect(await escrow.owed(await usdt.getAddress(), buyer.address)).to.equal(99_000_000n);
      await expect(escrow.connect(buyer).withdraw(await usdt.getAddress())).to.be.revertedWithCustomError(escrow, "TransferFailed");
      await usdt.setBlacklisted(buyer.address, false);
      await escrow.connect(buyer).withdraw(await usdt.getAddress());
      expect(await usdt.balanceOf(buyer.address)).to.equal(99_000_000n);
      await expect(escrow.connect(buyer).withdraw(await usdt.getAddress())).to.be.revertedWithCustomError(escrow, "BadAmount");
    });
  });

  describe("tokens that change after the deposit", function () {
    it("a token that starts taking a cut later still pays out and leaves nothing behind", async function () {
      const ctx = await deploy();
      const t = await (await ethers.getContractFactory("ToggleFeeToken")).deploy();
      await t.mint(ctx.seller.address, 1_000_000_000n);
      const key = await openToken(ctx, t);
      await t.setSkim(true);
      await ctx.escrow.connect(ctx.seller).release(key);
      expect(await t.balanceOf(ctx.buyer.address)).to.equal(99_000_000n - 990_000n);
      expect(await t.balanceOf(ctx.treasury.address)).to.equal(1_000_000n - 10_000n);
      expect(await t.balanceOf(await ctx.escrow.getAddress())).to.equal(0n);
    });
  });

  describe("hostile receivers", function () {
    it("a contract that refuses ETH gets a claim, and the claim pays out later", async function () {
      const ctx = await deploy();
      const { escrow, seller, arbiter } = ctx;
      const hostile = await (await ethers.getContractFactory("HostileReceiver")).deploy();
      const total = ethers.parseEther("1");
      await escrow.connect(seller).open(tradeId(5), await hostile.getAddress(), arbiter.address, ethers.ZeroAddress, total, 0n, FALLBACK, { value: total });
      const key = await escrow.keyOf(tradeId(5), seller.address);
      await hostile.arm(await escrow.getAddress(), key, true, false);
      await escrow.connect(seller).release(key);
      expect(await escrow.owed(ethers.ZeroAddress, await hostile.getAddress())).to.equal(total);
      await expect(hostile.pull(ethers.ZeroAddress)).to.be.revertedWithCustomError(escrow, "TransferFailed");
      await hostile.arm(await escrow.getAddress(), key, false, false);
      await hostile.pull(ethers.ZeroAddress);
      expect(await ethers.provider.getBalance(await hostile.getAddress())).to.equal(total);
    });

    it("re-entering during a payout cannot touch the escrow twice", async function () {
      const ctx = await deploy();
      const { escrow, seller, arbiter } = ctx;
      const hostile = await (await ethers.getContractFactory("HostileReceiver")).deploy();
      const total = ethers.parseEther("1");
      await escrow.connect(seller).open(tradeId(6), await hostile.getAddress(), arbiter.address, ethers.ZeroAddress, total, 0n, FALLBACK, { value: total });
      const key = await escrow.keyOf(tradeId(6), seller.address);
      await hostile.arm(await escrow.getAddress(), key, false, true);
      await escrow.connect(seller).release(key);
      expect((await escrow.escrows(key)).state).to.equal(2);
      expect(await escrow.owed(ethers.ZeroAddress, await hostile.getAddress())).to.equal(total);
      expect(await ethers.provider.getBalance(await escrow.getAddress())).to.equal(total);
    });

    it("the contract never holds more than its open escrows and claims", async function () {
      const ctx = await deploy();
      const { escrow, usdc, seller, buyer, arbiter } = ctx;
      const keys = [];
      for (let i = 1; i <= 5; i++) keys.push(await openToken(ctx, usdc, i, 10_000_000n * BigInt(i), 100_000n));
      await escrow.connect(seller).release(keys[0]);
      await escrow.connect(buyer).cancel(keys[1]);
      await escrow.connect(arbiter).resolve(keys[2], true);
      let open = 0n;
      for (const k of keys) {
        const e = await escrow.escrows(k);
        if (e.state === 1n) open += e.total;
      }
      expect(await usdc.balanceOf(await escrow.getAddress())).to.equal(open);
    });
  });
});
