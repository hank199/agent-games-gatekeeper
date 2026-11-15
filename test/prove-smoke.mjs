import fs from "node:fs";
import { createRequire } from "node:module";
const snarkjs = createRequire(import.meta.url)("snarkjs");

const wasm = fs.readFileSync(new URL("../circuits/gatekeeper.wasm", import.meta.url));
const zkey = fs.readFileSync(new URL("../circuits/gatekeeper_final.zkey", import.meta.url));

const VK = BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const RECIP = BigInt("0xDe42000000000000000000000000000000009f01");

const base = {
  taskId: "1",
  registeredVkHash: VK.toString(),
  proofVkHash: VK.toString(),
  minimum: "1000",
  publicBalance: "1460",
  expiryBlock: "19842201",
  currentBlock: "19832000",
  recipient: RECIP.toString(),
  conditionRecipient: RECIP.toString(),
  amount: "500",
  maxTransfer: "1000",
  salt: "1",
};

async function attempt(label, decision) {
  const inputs = { ...base, decision: String(decision) };
  const t0 = performance.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm, zkey);
    const dt = performance.now() - t0;
    const vk = await snarkjs.zKey.exportVerificationKey(zkey);
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`[${label}] decision=${decision} PROVED in ${dt.toFixed(0)}ms verify=${ok} publicSignals=${publicSignals.length}`);
    console.log("  signals:", JSON.stringify(publicSignals));
    return true;
  } catch (e) {
    const dt = performance.now() - t0;
    console.log(`[${label}] decision=${decision} FAILED in ${dt.toFixed(0)}ms: ${String(e.message || e).slice(0, 200)}`);
    return false;
  }
}

const t0 = performance.now();
const ok1 = await attempt("valid-condition", 1);
if (!ok1) await attempt("valid-condition", 0);
const rss = process.memoryUsage().rss / 1024 / 1024;
console.log(`total ${(performance.now() - t0).toFixed(0)}ms, rss ${rss.toFixed(0)}MB`);
