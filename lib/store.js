/**
 * Process-local state. Serverless instances are recycled, so this is a
 * best-effort seen-set and response cache: enough for reuse within a warm
 * instance (tasks of one round arrive minutes apart), not a durable ledger.
 * Set REDIS_URL/REDIS_TOKEN to use an Upstash-compatible REST store instead.
 */

const responses = new Map(); // task_id -> response body
const seenProofTx = new Set();
const MAX = 5000;

const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
const useRedis = Boolean(redisUrl && redisToken);

async function redis(cmd) {
  const res = await fetch(`${redisUrl}/${cmd.map(encodeURIComponent).join("/")}`, {
    headers: { authorization: `Bearer ${redisToken}` },
  });
  if (!res.ok) throw new Error(`redis ${res.status}`);
  return (await res.json()).result;
}

export function cached(taskId) {
  return responses.get(taskId);
}

export function remember(taskId, body) {
  if (responses.size >= MAX) responses.delete(responses.keys().next().value);
  responses.set(taskId, body);
}

export async function isReused(proofTx) {
  if (!proofTx) return false;
  const key = String(proofTx).toLowerCase();
  if (useRedis) {
    try {
      return (await redis(["EXISTS", `gk:tx:${key}`])) === 1;
    } catch {
      /* fall through to memory */
    }
  }
  return seenProofTx.has(key);
}

export async function markSeen(proofTx) {
  if (!proofTx) return;
  const key = String(proofTx).toLowerCase();
  if (useRedis) {
    try {
      await redis(["SET", `gk:tx:${key}`, "1", "EX", "604800"]);
      return;
    } catch {
      /* fall through to memory */
    }
  }
  if (seenProofTx.size >= MAX) seenProofTx.delete(seenProofTx.values().next().value);
  seenProofTx.add(key);
}
