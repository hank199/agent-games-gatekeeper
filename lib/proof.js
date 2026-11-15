import fs from "node:fs";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { DECISION_SIGNAL } from "./decision.js";

const snarkjs = createRequire(import.meta.url)("snarkjs");

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM_PATH = new URL("../circuits/gatekeeper.wasm", import.meta.url);
const ZKEY_PATH = new URL("../circuits/gatekeeper_final.zkey", import.meta.url);

let wasm;
let zkey;
let vk;

function load() {
  if (!wasm) wasm = fs.readFileSync(WASM_PATH);
  if (!zkey) zkey = fs.readFileSync(ZKEY_PATH);
  return { wasm, zkey };
}

export async function verificationKey() {
  if (!vk) {
    load();
    vk = await snarkjs.zKey.exportVerificationKey(zkey);
  }
  return vk;
}

function field(v, label) {
  const s = String(v ?? "").trim();
  if (!s) throw new Error(`missing field ${label}`);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^\d+$/.test(s)) return BigInt(s);
  throw new Error(`non-numeric field ${label}`);
}

function taskIdField(taskId) {
  const s = String(taskId ?? "");
  if (/^\d+$/.test(s)) return BigInt(s);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  const h = crypto.createHash("sha256").update(s).digest("hex");
  return BigInt("0x" + h) % BN254_R;
}

export function buildCircuitInput(task, decision) {
  const input = task.input || {};
  return {
    taskId: taskIdField(task.task_id).toString(),
    registeredVkHash: field(input.registered_vk, "registered_vk").toString(),
    proofVkHash: field(input.proof_vk, "proof_vk").toString(),
    minimum: field(input.minimum, "minimum").toString(),
    publicBalance: field(input.public_balance, "public_balance").toString(),
    expiryBlock: field(input.expiry_block, "expiry_block").toString(),
    currentBlock: field(input.current_block, "current_block").toString(),
    recipient: field(input.recipient, "recipient").toString(),
    conditionRecipient: field(input.condition_recipient, "condition_recipient").toString(),
    amount: field(input.amount, "amount").toString(),
    maxTransfer: field(input.max_transfer, "max_transfer").toString(),
    decision: String(DECISION_SIGNAL[decision] ?? 0),
    salt: process.env.GK_SALT || "1",
  };
}

/** Generate the Groth16 proof of our decision. Returns { proof, publicSignals }. */
export async function proveDecision(task, decision) {
  load();
  const inputs = buildCircuitInput(task, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm, zkey);
  return { proof, publicSignals };
}

export async function verifyLocal(proof, publicSignals) {
  const key = await verificationKey();
  return snarkjs.groth16.verify(key, publicSignals, proof);
}
