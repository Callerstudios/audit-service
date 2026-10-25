# Universal Audit Service

A standalone HTTP service for receiving security audit events from independent software systems. The first version uses Express, TypeScript, and Cloud Firestore. Producers can be written in any language that can make HTTPS requests and compute HMAC-SHA256 signatures.

This starter implements **Stage 1: secure ingestion** from the supplied design. It is a foundation for development, not a production claim of tamper-proof storage.

## What is included

- HMAC-SHA256 producer authentication with timestamp freshness and one-time nonces.
- A versioned JSON event contract and bounded batch ingestion.
- Firestore transaction-based idempotency by producer and batch ID.
- Server-generated receipts, retrievable by the producer that submitted them.
- Payload-size and in-process rate limits, health endpoints, and generic error responses.
- A Firestore rules file that denies direct client access. The Admin SDK uses Google Cloud IAM and bypasses Firestore Security Rules.

Not included yet: signed receipts, hash-chain checkpoints, immutable archive, reviewer/search API, producer-management UI/API, delivery worker/outbox integration, alerts, key lifecycle automation, backup/restore procedures, or production deployment configuration.

## Important Firestore limit

The HTTP API has no update or delete operation for accepted events. That does **not** make Firestore records immutable. This service uses the Firebase Admin SDK, which is privileged; an operator or compromised Google Cloud identity with sufficient permissions can change or delete records. Firestore Security Rules do not constrain the Admin SDK. A hash chain stored only in the same mutable database would not solve this trust problem either.

Use this version to develop and integrate the ingestion contract. Before relying on the service for custody of high-risk evidence, add separately administered immutable archival/checkpoints, signing-key custody, independent monitoring, and verified recovery. Keep privileged business operations closed until the required custody guarantees are actually deployed and tested.

## Requirements

- Node.js 22 or newer.
- A Firebase project with Cloud Firestore enabled.
- Application Default Credentials with access to that project. In Google Cloud, use a dedicated service account with the narrowest available permissions. For local development, use `gcloud auth application-default login` or a service-account file that is never committed.

## Run locally

```bash
npm install
cp .env.example .env
```

Set `FIREBASE_PROJECT_ID`. Generate a 32-byte or longer random secret for each producer key, for example with `openssl rand -hex 32`, then put the value in `PRODUCER_KEYS_JSON`. Do not use the example placeholder as a real credential.

For a local Firestore Emulator, start it with the Firebase CLI and set `FIRESTORE_EMULATOR_HOST=127.0.0.1:8080` in `.env`. Emulator data is for development only.

```bash
npm run dev
```

The live endpoint is `GET http://localhost:4000/v1/health/live`. The ready endpoint checks Firestore connectivity at `GET http://localhost:4000/v1/health/ready`.

## Producer configuration and key rotation

`PRODUCER_KEYS_JSON` maps producer ID to one or more key IDs and secrets:

```json
{
  "cycling-club-manager": {
    "key-2026-01": "a-long-random-secret-value-at-least-32-characters"
  },
  "another-software-system": {
    "key-2026-01": "another-long-random-secret-value-at-least-32-characters"
  }
}
```

The service accepts any producer configured this way. During rotation, add a new key ID while keeping the old one temporarily, update the producer, then remove the old key after requests have moved to the new key. For deployment, inject secrets from a managed secret store instead of committing them to source or putting them in a plain-text deployment file.

## API

### `POST /v1/events`

Submit a batch. Use the **same `batchId` and exact logical payload** when retrying after a timeout. A successful first submission returns `201`; a repeated identical submission returns the original receipt with `200`. Reusing a batch ID with different content, or sending an event ID already accepted in another batch, returns `409`.

```json
{
  "schemaVersion": 1,
  "batchId": "outbox-batch-01JAZ8D4P7F1",
  "events": [
    {
      "eventId": "01JAZ8D4P7F1J4G95M0N4B8T9A",
      "eventType": "access.grant_rejected",
      "occurredAt": "2026-10-25T10:30:00Z",
      "correlationId": "request-481",
      "actor": { "type": "user", "id": "user-123" },
      "target": { "type": "role_assignment", "id": "assignment-456" },
      "outcome": "denied",
      "reasonCode": "INSUFFICIENT_APPROVALS",
      "metadata": { "approvalCount": 1 }
    }
  ]
}
```

`eventType` uses lowercase dotted names (for example, `auth.login_success`). `outcome` must be `success`, `failure`, `denied`, or `unknown`. Unknown event fields are rejected. Event IDs must be unique within the batch and unique for a producer. The configured body-size and batch-count limits apply.

Do not submit passwords, tokens, cookies, session IDs, secrets, recovery codes, or unnecessary personal data. The service rejects metadata keys that look sensitive, but no key-name filter can reliably detect every sensitive value. Producers remain responsible for their event content.

### `GET /v1/receipts/{receiptId}`

Returns a receipt only to the producer that submitted it. A receipt confirms that the service committed the batch to Firestore. In this initial version it is **not cryptographically signed** and is not an independent proof against a privileged Firestore administrator.

### Health

- `GET /v1/health/live`: process is responding.
- `GET /v1/health/ready`: Firestore can be queried.

Health routes do not require producer authentication and return no configuration details.

## HMAC signing contract

Each request to `/v1` requires these headers:

- `X-Producer-Id`: configured producer ID.
- `X-Key-Id`: configured key ID.
- `X-Timestamp`: Unix timestamp in seconds.
- `X-Nonce`: a fresh random value of 16–128 characters (`A-Z`, `a-z`, digits, `_`, `-`). Never reuse it.
- `X-Signature`: lowercase or uppercase hex HMAC-SHA256.

Sign the exact UTF-8 bytes sent as the request body. For a request with no body, sign an empty string. Build the signed message as five lines, separated by `\n`, with **no final newline**:

```text
HTTP_METHOD
PATH_AND_QUERY
TIMESTAMP
NONCE
RAW_BODY
```

For example: `POST`, `/v1/events`, timestamp, nonce, then the exact JSON string. The server allows a limited clock skew, checks the signature using a timing-safe comparison, and records the nonce to reject replay. Requests outside the configured time window are rejected. Send requests only over HTTPS outside local development.

Node.js signing example (the body string used for signing must be the same string passed to `fetch`):

```ts
import { createHmac, randomBytes } from "node:crypto";

const producerId = "cycling-club-manager";
const keyId = "key-2026-01";
const secret = process.env.AUDIT_PRODUCER_SECRET!;
const method = "POST";
const pathAndQuery = "/v1/events";
const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = randomBytes(24).toString("base64url");
const body = JSON.stringify({
  schemaVersion: 1,
  batchId: "outbox-batch-01JAZ8D4P7F1",
  events: [{
    eventId: "01JAZ8D4P7F1J4G95M0N4B8T9A",
    eventType: "auth.login_success",
    occurredAt: new Date().toISOString(),
    outcome: "success",
    actor: { type: "user", id: "user-123" }
  }]
});
const message = [method, pathAndQuery, timestamp, nonce, body].join("\n");
const signature = createHmac("sha256", secret).update(message, "utf8").digest("hex");

const response = await fetch(`https://audit.example.com${pathAndQuery}`, {
  method,
  headers: {
    "content-type": "application/json",
    "x-producer-id": producerId,
    "x-key-id": keyId,
    "x-timestamp": timestamp,
    "x-nonce": nonce,
    "x-signature": signature
  },
  body
});
```

Include query parameters in `PATH_AND_QUERY` exactly as sent. For `GET /v1/receipts/{receiptId}`, sign the empty body and include the exact path.

## Firestore collections

- `auditEvents`: one event record per event ID, scoped by producer.
- `ingestionBatches`: idempotency record and digest for each accepted batch.
- `auditReceipts`: producer-scoped receipt data.
- `requestNonces`: used nonces for replay prevention.

Configure a Firestore TTL policy on `requestNonces.expiresAt` (collection group `requestNonces`) so replay-protection documents are eventually removed. TTL deletion is asynchronous; nonce freshness is enforced separately by timestamp validation. Do not enable TTL on events, batches, or receipts until a retention policy has been explicitly decided.

## Operational notes before production

- The included rate limiter stores counts in process memory. Use a shared rate-limit store when running multiple replicas.
- Configure HTTPS at the load balancer or hosting platform, restrict network access where possible, and monitor authentication failures and storage errors.
- Use a dedicated Firebase/GCP project and service identity for this service, separate from producer applications. Security Rules deny direct client access, but Google Cloud IAM still controls Admin SDK access.
- Firestore transaction writes are atomic. The transaction function may be retried by Firestore, so it has no external side effects.
- Add an independent immutable archive/checkpoint and signed receipts before claiming tamper-evident custody. A hash chain or receipt that can be rewritten by the same privileged administrator does not create independent evidence.
- Connect the producer's transactional outbox only after the producer can retry with the same batch ID, verify receipt responses, and reconcile accepted batches after timeouts.
