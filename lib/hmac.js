import crypto from "node:crypto";

export const SIG_HEADER = "x-agent-games-signature";

function normalize(sig) {
  let s = String(sig || "").trim();
  if (!s) return [];
  const out = [s.toLowerCase()];
  if (s.toLowerCase().startsWith("sha256=")) out.push(s.slice(7).toLowerCase());
  try {
    out.push(Buffer.from(s, "base64").toString("hex").toLowerCase());
  } catch {
    /* not base64 */
  }
  return out;
}

/** Constant-time HMAC check over the RAW body. Must run before JSON.parse. */
export function verify(rawBody, headerValue, secret) {
  if (!secret) return false;
  if (!headerValue) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  const expectedBuf = Buffer.from(expected, "hex");
  for (const candidate of normalize(headerValue)) {
    if (!/^[0-9a-f]+$/.test(candidate) || candidate.length !== expected.length) continue;
    const buf = Buffer.from(candidate, "hex");
    if (buf.length === expectedBuf.length && crypto.timingSafeEqual(buf, expectedBuf)) return true;
  }
  return false;
}

export function sign(rawBody, secret) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
