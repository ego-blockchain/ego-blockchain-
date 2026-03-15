/**
 * Example: check balance and submit a transaction.
 * Run with: npx ts-node src/examples/send.ts
 */
import { EgoClient, toUEgoc, fromUEgoc } from "../index";

const client = new EgoClient({ rpcUrl: "http://localhost:8545" });

async function main() {
  // 1. Check node health
  const health = await client.health();
  console.log(`Node healthy — block height: ${health.block_height}`);

  // 2. Check sender balance
  const SENDER = "0x" + "aa".repeat(20);
  const balResult = await client.getBalance(SENDER);
  console.log(`Balance: ${fromUEgoc(balResult.balance_uegoc)}`);

  // 3. Submit a transfer
  const result = await client.submitTx({
    from:   SENDER,
    to:     "0x" + "bb".repeat(20),
    amount: toUEgoc(1.5).toString(),   // 1.5 EGOC
    nonce:  0,
  });
  console.log(`TX submitted: ${result.tx_hash}`);

  // 4. Wait for confirmation (next batch window ~50 ms)
  const height = await client.waitForBlocks(1, 100, 5_000);
  console.log(`Confirmed at block ${height}`);
}

main().catch(console.error);
