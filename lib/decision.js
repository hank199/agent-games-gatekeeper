/**
 * Deterministic policy engine for Proof Gatekeeper.
 * Order follows the published trap encyclopedia. The circuit is the referee,
 * so this must agree with the constraints proven in test/rule-matrix.mjs:
 *   APPROVE iff proofVk == registeredVk
 *           && currentBlock < expiryBlock
 *           && recipient == conditionRecipient
 *           && publicBalance >= minimum
 *           && amount <= maxTransfer
 */

export const REASON = {
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_INPUT: "INVALID_INPUT",
};

function big(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "bigint") return v;
  const s = String(v).trim();
  if (!s) return null;
  try {
    return s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s);
  } catch {
    return null;
  }
}

function hex(v) {
  const b = big(v);
  return b === null ? null : b.toString(16).toLowerCase();
}

export function evaluate(input, isReused) {
  if (!input || typeof input !== "object") {
    return { decision: "REJECT", reason_code: REASON.INVALID_INPUT };
  }

  const fields = {
    registeredVk: hex(input.registered_vk),
    proofVk: hex(input.proof_vk),
    minimum: big(input.minimum),
    publicBalance: big(input.public_balance),
    expiryBlock: big(input.expiry_block),
    currentBlock: big(input.current_block),
    recipient: hex(input.recipient),
    conditionRecipient: hex(input.condition_recipient),
    amount: big(input.amount),
    maxTransfer: big(input.max_transfer),
  };

  if (Object.values(fields).some((v) => v === null)) {
    return { decision: "REJECT", reason_code: REASON.INVALID_INPUT };
  }

  const reject = (reason_code) => ({ decision: "REJECT", reason_code });

  if (fields.proofVk !== fields.registeredVk) return reject(REASON.VK_SUBSTITUTION);
  if (isReused) return reject(REASON.PROOF_REUSED);
  if (fields.publicBalance < fields.minimum) return reject(REASON.THRESHOLD_MISMATCH);
  if (fields.currentBlock >= fields.expiryBlock) return reject(REASON.EXPIRED_CONDITION);
  if (fields.recipient !== fields.conditionRecipient) return reject(REASON.RECIPIENT_MISMATCH);
  if (fields.amount > fields.maxTransfer) return reject(REASON.AMOUNT_OVERFLOW);

  return { decision: "APPROVE", reason_code: REASON.VALID };
}

export const DECISION_SIGNAL = { APPROVE: 1, REJECT: 0 };
