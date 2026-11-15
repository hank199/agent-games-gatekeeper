/**
 * Local replay harness: signs envelopes exactly as the platform does,
 * posts them to the running agent, and verifies the response signature,
 * the decision, and (when present) the Groth16 proof against the
 * platform's own verification key.
 *
 *   PORT=8787 AGENT_GAMES_HMAC_SECRET=dev-secret node scripts/dev-server.mjs
 *   AGENT_GAMES_HMAC_SECRET=dev-secret node scripts/replay.mjs
 */
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
const snarkjs = createRequire(import.meta.url)("snarkjs");

const BASE = process.env.AGENT_URL || "http://127.0.0.1:8787/agent";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "dev-secret";
const SIG = "x-agent-games-signature";

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK2 = "0xa4c100000000000000000000000000000000b8ff";
const RECIP = "0xDe42000000000000000000000000000000009f01";
const RECIP2 = "0xBeef000000000000000000000000000000009f02";

const hmac = (body) => crypto.createHmac("sha256", SECRET).update(body).digest("hex");

const base = {
  registered_vk: VK,
  proof_vk: VK,
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: RECIP,
  condition_recipient: RECIP,
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xtx_default",
};

const RUN = crypto.randomBytes(3).toString("hex");
let n = 0;
const cases = [
  ["valid", {}, "APPROVE", "VALID_CONDITION"],
  ["vk_substitution", { proof_vk: VK2 }, "REJECT", "VK_SUBSTITUTION"],
  ["threshold_mismatch", { public_balance: "999" }, "REJECT", "THRESHOLD_MISMATCH"],
  ["expired_condition", { current_block: 19842201 }, "REJECT", "EXPIRED_CONDITION"],
  ["recipient_mismatch", { condition_recipient: RECIP2 }, "REJECT", "RECIPIENT_MISMATCH"],
  ["amount_overflow", { amount: "1001" }, "REJECT", "AMOUNT_OVERFLOW"],
  ["valid_boundary", { public_balance: "1000", amount: "1000" }, "APPROVE", "VALID_CONDITION"],
];

async function post(path, obj, { signIt = true, secret = SECRET } = {}) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { "content-type": "application/json" };
  if (signIt) headers[SIG] = crypto.createHmac("sha256", secret).update(body).digest("hex");
  const res = await fetch(path, { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get(SIG), text };
}

const vk = await snarkjs.zKey.exportVerificationKey(
  fs.readFileSync(new URL("../circuits/gatekeeper_final.zkey", import.meta.url))
);

let pass = 0;
let fail = 0;
const check = (ok, msg) => {
  if (ok) pass++;
  else {
    fail++;
    console.log("  FAIL:", msg);
  }
};

// 1. preflight
{
  const r = await post(BASE, { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  const body = JSON.parse(r.text);
  check(r.status === 200 && body.ok === true && body.protocolVersion === "v1", `preflight body ${r.text}`);
  check(r.sig === hmac(r.text), "preflight response signature");
  console.log(`preflight ${r.status} ok=${body.ok}`);
}

// 2. unsigned request must be rejected
{
  const r = await post(BASE, { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_unsigned" }, { signIt: false });
  check(r.status === 401, `unsigned rejected (got ${r.status})`);
  console.log(`unsigned request -> ${r.status}`);
}

// 3. decision cases
for (const [label, overrides, wantDecision, wantReason] of cases) {
  const taskId = `gk_${RUN}_${String(++n).padStart(3, "0")}`;
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...base, proof_tx: `0x${label}`, ...overrides },
  };
  const t0 = Date.now();
  const r = await post(BASE, task);
  const ms = Date.now() - t0;
  const body = JSON.parse(r.text);
  check(r.status === 200, `${label}: status ${r.status}`);
  check(body.decision === wantDecision, `${label}: decision ${body.decision} != ${wantDecision}`);
  check(body.reason_code === wantReason, `${label}: reason ${body.reason_code} != ${wantReason}`);
  check(r.sig === hmac(r.text), `${label}: response signature`);
  let proofOk = "none";
  if (body.proof && body.public_signals) {
    proofOk = await snarkjs.groth16.verify(vk, body.public_signals, body.proof);
    check(proofOk === true, `${label}: proof did not verify`);
    check(body.public_signals.length === 13, `${label}: public signal count ${body.public_signals.length}`);
  }
  console.log(`${label.padEnd(20)} ${body.decision.padEnd(7)} ${String(body.reason_code).padEnd(18)} proof=${proofOk} ${ms}ms`);
}

// 4. idempotent replay of the same task_id
{
  const task = { type: "agent-games.proof-gatekeeper.v1", task_id: `gk_${RUN}_001`, mode: "competition", input: { ...base, proof_tx: "0xvalid" } };
  const r = await post(BASE, task);
  check(r.status === 200, "idempotent replay status");
  console.log(`idempotent replay -> ${r.status}`);
}

// 5. proof reuse: a fresh task carrying an already-accepted proof_tx
{
  const task = { type: "agent-games.proof-gatekeeper.v1", task_id: `gk_${RUN}_reuse`, mode: "competition", input: { ...base, proof_tx: "0xvalid" } };
  const r = await post(BASE, task);
  const body = JSON.parse(r.text);
  check(body.reason_code === "PROOF_REUSED", `reuse: got ${body.reason_code}`);
  console.log(`proof_reused         ${body.decision} ${body.reason_code}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
