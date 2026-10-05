const fs = require("fs");
const path = require("path");
const { TronWeb } = require("tronweb");

const HOSTS = {
  nile: "https://nile.trongrid.io",
  shasta: "https://api.shasta.trongrid.io",
  mainnet: "https://api.trongrid.io",
};

function artifact(name, file) {
  const p = path.join(__dirname, "..", "artifacts", "contracts", file, `${name}.json`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

async function deploy(tw, art, parameters) {
  const c = await tw.contract().new({
    abi: art.abi,
    bytecode: art.bytecode,
    feeLimit: 1_500_000_000,
    callValue: 0,
    userFeePercentage: 100,
    parameters,
  });
  return tw.address.fromHex(c.address);
}

async function main() {
  const key = process.env.TRON_PRIVATE_KEY;
  const network = process.env.TRON_NETWORK || "nile";
  if (!key || !HOSTS[network]) {
    console.error("Set TRON_PRIVATE_KEY (hex, no 0x) and TRON_NETWORK=nile|shasta|mainnet. Run `npx hardhat compile` first.");
    process.exit(1);
  }
  if (network === "mainnet" && process.env.I_UNDERSTAND_MAINNET !== "yes") {
    console.error("Refusing to deploy to Tron mainnet without I_UNDERSTAND_MAINNET=yes.");
    process.exit(1);
  }
  const tw = new TronWeb({ fullHost: HOSTS[network], privateKey: key });
  const feeReceiver = process.env.FEE_RECEIVER || tw.defaultAddress.base58;
  const out = { network, deployer: tw.defaultAddress.base58, feeReceiver };
  out.escrow = await deploy(tw, artifact("EgoEscrow", "EgoEscrow.sol"), [feeReceiver]);
  if (process.env.TEST_TOKENS) {
    const token = artifact("MockToken", "test/Mocks.sol");
    out.usdt = await deploy(tw, token, ["Test Tether USD", "USDT", 6]);
    if (process.env.MINT_TO) {
      const c = await tw.contract(token.abi, out.usdt);
      await c.mint(process.env.MINT_TO, process.env.MINT_AMOUNT || "1000000000000").send({ feeLimit: 100_000_000 });
    }
  }
  console.log(JSON.stringify(out));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
