# Proof Gatekeeper agent — zkVerify Agent Games

Autonomous agent endpoint for **Event 01 · Proof Gatekeeper** at
`agentgames.zkverify.io`. The platform POSTs signed task envelopes to a public
HTTPS endpoint; the agent answers `APPROVE`/`REJECT` with a reason code **and**
its own Groth16 proof of that decision, which the platform re-verifies against
its registered `vk_hash`.

## What it does

1. Verifies `x-agent-games-signature` (HMAC-SHA256) over the **raw** body before
   parsing JSON. Fail closed on mismatch.
2. Applies the deterministic rule set in the documented trap order.
3. Proves the decision with the platform's `gatekeeper` circuit (snarkjs,
   Groth16/BN128) and returns `proof` + `public_signals`.
4. Signs the response body with the same secret.
5. Caches per `task_id` (idempotency) and tracks accepted `proof_tx` references
   so replayed proofs are rejected.

## Decision rules (matches the circuit, verified empirically)

| Check | Fail → reason code |
|---|---|
| `proof_vk` == `registered_vk` | `VK_SUBSTITUTION` |
| `proof_tx` not already accepted | `PROOF_REUSED` |
| `public_balance` >= `minimum` | `THRESHOLD_MISMATCH` |
| `current_block` < `expiry_block` | `EXPIRED_CONDITION` |
| `recipient` == `condition_recipient` | `RECIPIENT_MISMATCH` |
| `amount` <= `max_transfer` | `AMOUNT_OVERFLOW` |
| all pass | `VALID_CONDITION` → `APPROVE` |

`test/rule-matrix.mjs` proves each boundary against the real circuit: equality
is allowed for threshold and max transfer, expiry is inclusive
(`current >= expiry` is expired), and the circuit does **not** constrain
`amount <= public_balance`.

## Circuit inputs (13 public signals)

Recovered from the wasm and confirmed by generating and verifying proofs:

`taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt`

`decision`: APPROVE=1, REJECT=0. `salt` defaults to `1` (`GK_SALT`).

## Endpoints

- `POST /agent` — task envelopes (`agent-games.proof-gatekeeper.v1`) and
  preflight (`agent-games.preflight.v1` → `{ok:true,protocolVersion:"v1"}`).
- `GET /agent` — health probe.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=dev-secret PORT=8787 npm run dev   # terminal 1
AGENT_GAMES_HMAC_SECRET=dev-secret npm run replay          # terminal 2
```

`npm run replay` signs envelopes like the platform, checks the response
signature, checks every decision, and verifies each returned proof against the
platform's verification key. Current result: **47/47 checks pass**, warm proof
generation ~150 ms, cold ~600–850 ms, RSS ~150 MB.

## Deploy

Vercel Hobby: 2 GB memory, 300 s max duration, no idle-sleeping container.

```bash
npx vercel --prod
```

`vercel.json` rewrites `/agent` → `/api/agent` and bundles `circuits/`.
Set `AGENT_GAMES_HMAC_SECRET` from the dashboard's **Rotate Secret** in the
Vercel project environment — never in the repo.

## Known unknowns (resolve in practice mode)

- Whether the platform recomputes `public_signals` and compares them to the
  task fields, and whether it expects a specific `salt`.
- `taskId` encoding for non-numeric ids (sha256 mod BN254 field as a fallback).
- `PROOF_REUSED` detection is process-local unless `UPSTASH_REDIS_*` is set;
  serverless instances recycle between rounds.
