require("@nomicfoundation/hardhat-toolbox");

const accounts = process.env.DEPLOYER_KEY ? [process.env.DEPLOYER_KEY] : [];

module.exports = {
  solidity: {
    version: "0.8.26",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "paris",
    },
  },
  networks: {
    local: { url: process.env.LOCAL_RPC || "http://127.0.0.1:8645" },
    sepolia: { url: process.env.SEPOLIA_RPC || "https://ethereum-sepolia-rpc.publicnode.com", chainId: 11155111, accounts },
    bscTestnet: { url: process.env.BSC_TESTNET_RPC || "https://bsc-testnet-rpc.publicnode.com", chainId: 97, accounts },
    amoy: { url: process.env.AMOY_RPC || "https://rpc-amoy.polygon.technology", chainId: 80002, accounts },
    ethereum: { url: process.env.ETHEREUM_RPC || "https://ethereum-rpc.publicnode.com", chainId: 1, accounts },
    bsc: { url: process.env.BSC_RPC || "https://bsc-rpc.publicnode.com", chainId: 56, accounts },
    polygon: { url: process.env.POLYGON_RPC || "https://polygon-bor-rpc.publicnode.com", chainId: 137, accounts },
  },
};
