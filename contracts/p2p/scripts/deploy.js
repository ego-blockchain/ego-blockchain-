const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const feeReceiver = process.env.FEE_RECEIVER || deployer.address;
  const escrow = await (await ethers.getContractFactory("EgoEscrow")).deploy(feeReceiver);
  await escrow.waitForDeployment();
  const out = {
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    escrow: await escrow.getAddress(),
    feeReceiver,
  };
  if (process.env.TEST_TOKENS) {
    const decimals = Number(process.env.TOKEN_DECIMALS || 6);
    const Token = await ethers.getContractFactory("MockToken");
    for (const [name, symbol] of [["Test Tether USD", "USDT"], ["Test USD Coin", "USDC"]]) {
      const t = await Token.deploy(name, symbol, decimals);
      await t.waitForDeployment();
      out[symbol.toLowerCase()] = await t.getAddress();
      if (process.env.MINT_TO) {
        await (await t.mint(process.env.MINT_TO, BigInt(process.env.MINT_AMOUNT || "1000000000000"))).wait();
      }
    }
  }
  console.log(JSON.stringify(out));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
