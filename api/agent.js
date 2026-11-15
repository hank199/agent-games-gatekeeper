import { evaluate } from "../lib/decision.js";
import { verify, sign, SIG_HEADER } from "../lib/hmac.js";
import { proveDecision } from "../lib/proof.js";
import { cached, remember, isReused, markSeen } from "../lib/store.js";

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const SKIP_HMAC = process.env.SKIP_HMAC === "1";
const PROVE = process.env.GK_PROOF !== "off";
const PROOF_BUDGET_MS = Number(process.env.GK_PROOF_BUDGET_MS || 45000);
const MAX_BODY = 1024 * 1024;

function readRaw(req) {
  return new Promise((resolve, reject) => {
    if (Buffer.isBuffer(req.body)) return resolve(req.body);
    if (typeof req.body === "string") return resolve(Buffer.from(req.body));
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function send(res, status, obj, secret, signed = true) {
  const body = Buffer.from(JSON.stringify(obj));
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  if (signed && secret) res.setHeader(SIG_HEADER, sign(body, secret));
  res.end(body);
}

export default async function handler(req, res) {
  const started = Date.now();

  if (req.method === "GET") {
    return send(res, 200, { ok: true, agent: "proof-gatekeeper", protocolVersion: "v1" }, SECRET, false);
  }
  if (req.method !== "POST") {
    return send(res, 405, { ok: false, error: "method_not_allowed" }, SECRET, false);
  }

  let raw;
  try {
    raw = await readRaw(req);
  } catch {
    return send(res, 413, { ok: false, error: "body_too_large" }, SECRET, false);
  }

  if (!SKIP_HMAC) {
    const header = req.headers?.[SIG_HEADER] || req.headers?.[SIG_HEADER.toUpperCase()];
    if (!verify(raw, header, SECRET)) {
      return send(res, 401, { ok: false, error: "bad_signature" }, SECRET, false);
    }
  }

  let task;
  try {
    task = JSON.parse(raw.toString("utf8"));
  } catch {
    return send(res, 400, { ok: false, error: "bad_json" }, SECRET);
  }

  if (task?.type === "agent-games.preflight.v1") {
    return send(res, 200, { ok: true, protocolVersion: "v1" }, SECRET);
  }

  if (task?.type !== "agent-games.proof-gatekeeper.v1") {
    return send(res, 400, { ok: false, error: "unknown_task_type" }, SECRET);
  }

  const taskId = String(task.task_id || "");
  const hit = cached(taskId);
  if (hit) return send(res, 200, hit, SECRET);

  const proofTx = task.input?.proof_tx;
  const reused = await isReused(proofTx);
  const { decision, reason_code } = evaluate(task.input, reused);

  const out = { decision, reason_code };

  if (PROVE && reason_code !== "PROOF_REUSED") {
    const budget = Math.max(5000, Math.min(PROOF_BUDGET_MS, Number(task.deadline_at ? Date.parse(task.deadline_at) - Date.now() - 8000 : PROOF_BUDGET_MS)));
    try {
      const proved = await Promise.race([
        proveDecision(task, decision),
        new Promise((_, rej) => setTimeout(() => rej(new Error("proof_budget_exceeded")), budget)),
      ]);
      out.proof = proved.proof;
      out.public_signals = proved.publicSignals;
    } catch (err) {
      console.error(JSON.stringify({ evt: "proof_failed", taskId, msg: String(err?.message || err) }));
    }
  }

  if (decision === "APPROVE") await markSeen(proofTx);

  remember(taskId, out);
  console.log(JSON.stringify({ evt: "decision", taskId, decision, reason_code, proved: Boolean(out.proof), ms: Date.now() - started }));
  return send(res, 200, out, SECRET);
}
