import fs from "node:fs";
import { createRequire } from "node:module";
const snarkjs = createRequire(import.meta.url)("snarkjs");

const wasm = fs.readFileSync(new URL("../circuits/gatekeeper.wasm", import.meta.url));
const zkey = fs.readFileSync(new URL("../circuits/gatekeeper_final.zkey", import.meta.url));

const VK = BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const VK2 = BigInt("0xa4c100000000000000000000000000000000b8ff");
const RECIP = BigInt("0xDe42000000000000000000000000000000009f01");
const RECIP2 = BigInt("0xBeef000000000000000000000000000000009f02");

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

async function can(overrides, decision) {
  const inputs = { ...base, ...overrides, decision: String(decision) };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm, zkey);
    const vk = await snarkjs.zKey.exportVerificationKey(zkey);
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    return { ok, signals: publicSignals };
  } catch (e) {
    return { ok: false, err: String(e.message || e).slice(0, 90) };
  }
}

const cases = [
  ["valid", {}],
  ["vk_mismatch", { proofVkHash: VK2.toString() }],
  ["threshold_low", { publicBalance: "999" }],
  ["threshold_equal", { publicBalance: "1000" }],
  ["expired_gt", { currentBlock: "19842202" }],
  ["expired_eq", { currentBlock: "19842201" }],
  ["recipient_mismatch", { conditionRecipient: RECIP2.toString() }],
  ["amount_overflow", { amount: "1001" }],
  ["amount_eq_max", { amount: "1000" }],
  ["amount_gt_balance", { amount: "1500", maxTransfer: "2000" }],
  ["balance_zero", { publicBalance: "0", minimum: "0" }],
  ["amount_zero_min", { amount: "0", minimum: "0" }],
  ["zero_amount", { amount: "0" }],
];

const t0 = performance.now();
for (const [label, ov] of cases) {
  const a = await can(ov, 1);
  const r = await can(ov, 0);
  console.log(`${label.padEnd(18)} APPROVE=${a.ok ? "ok " : "no "} REJECT=${r.ok ? "ok " : "no "} ${a.ok || r.ok ? "" : (a.err || "")}`);
}
console.log(`elapsed ${(performance.now() - t0).toFixed(0)}ms`);
process.exit(0);
