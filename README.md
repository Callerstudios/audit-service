# Universal Audit Service

A standalone Express, TypeScript, and Firestore service for receiving and reviewing security audit events from independent software systems. Any trusted server that can make HTTPS requests and compute HMAC-SHA256 can act as a producer.

This is a functional first version of the service: it accepts signed event batches, creates signed receipts, links events into a per-producer hash chain, supports producer-scoped idempotent retries, allows authorized reviewers to search and verify records, and logs reviewer access.

## What the service provides

- Producer HMAC authentication with timestamp checks and single-use nonces.
- Reviewer HMAC authentication with separate credentials and read-only audit routes.
- Versioned event validation and bounded batches.
- Firestore transactions for batch idempotency and per-producer event sequencing.
- Ed25519-signed receipts and a public-key endpoint for signature verification.
- Event hash links and a batch verification endpoint.
- Search by producer, event type, outcome, actor ID, target ID, and event time range, with pagination.
- Reviewer access records for successful searches, event reads, and verification requests.
- Firestore Rules that deny direct client access. The Firebase Admin SDK uses Google Cloud IAM and bypasses Security Rules.

## Security boundary

The HTTP API does not provide a way to update or delete accepted events. Firestore itself is still mutable to privileged Google Cloud identities. A project administrator or compromised identity with sufficient permissions can rewrite Firestore events, receipts, chain heads, and reviewer logs. The service's Ed25519 signature helps detect changed receipt contents if a client already trusts the signing public key. It does not protect against compromise of the signing private key.

This version is tamper-evident within the service boundary; it is not independent immutable custody. Before using it as evidence for high-risk privileged operations, add an archive or checkpoint in independently administered immutable storage, protect signing keys in a managed key store, and validate backup and recovery procedures. Keep those operations closed until the controls required by your governance policy are deployed and verified.

## Requirements and local setup

- Node.js 22 or newer.
- A Firebase project with Cloud Firestore enabled.
- A service account with permission to read and write the service's Firestore data.
- Producer and reviewer keys, plus an Ed25519 key pair for receipt signing.

Install and prepare local configuration:

```bash
npm install
cp .env.example .env
```

Set `FIREBASE_PROJECT_ID` to the Firestore project the service should use. For local development, either set `FIREBASE_KEY` to the service-account JSON as a single-line JSON string or leave it empty and use Application Default Credentials with `gcloud auth application-default login`. In either case, the credential needs access to the project named by `FIREBASE_PROJECT_ID`.

Generate separate random producer and reviewer secrets (at least 32 characters), for example with `openssl rand -hex 32`, then configure them in `PRODUCER_KEYS_JSON` and `REVIEWER_KEYS_JSON`. The producer secret belongs in the sending software; the reviewer secret belongs only to authorized review clients.

Generate the Ed25519 receipt-signing key pair:

```bash
openssl genpkey -algorithm Ed25519 -out receipt-private.pem
openssl pkey -in receipt-private.pem -pubout -out receipt-public.pem
```

Put the private PEM in `RECEIPT_SIGNING_PRIVATE_KEY` and set a unique `RECEIPT_KEY_ID`. Use escaped newlines (`\n`) if storing the PEM as a single-line environment value. Keep the private key secret. The current public key is returned by `GET /v1/keys`; store and pin it in trusted clients through a channel independent of this service. Keep old public keys in `RECEIPT_PUBLIC_KEYS_JSON` when rotating signing keys so historical signatures remain verifiable.

For a local Firestore Emulator, set `FIRESTORE_EMULATOR_HOST=127.0.0.1:8080` in `.env` and start the emulator with the Firebase CLI. Emulator data is for development only.

Deploy the Firestore rules and search indexes with the Firebase CLI after selecting the correct Firebase project:

```bash
firebase use your-firebase-project-id
npm run deploy:firestore
```

```bash
npm run dev
```

For Render, the repository includes `render.yaml`. Connect the repository as a Blueprint and provide the prompted secret values. The service uses Render's `PORT` environment variable and its `/v1/health/live` health check. Set `FIREBASE_KEY` to the full service-account JSON value. The Blueprint keeps credential values out of the file.

The service reads `PORT` from the environment (Render provides it automatically; local default is `4000`) and binds to `0.0.0.0`.

## Firebase credentials on Render

The service supports a conventional Firebase service-account key in `FIREBASE_KEY`. In Render, add `FIREBASE_KEY` as a secret environment variable and paste the full service-account JSON as its value. Do not commit that JSON to GitHub or include it in a `render.yaml` file. Set `FIREBASE_PROJECT_ID` separately to the project where this service's Firestore lives. The service-account identity must have access to that target project; the `project_id` inside the key does not grant access by itself.

You can also upload the JSON as a Render Secret File and set `GOOGLE_APPLICATION_CREDENTIALS` to its path. If `FIREBASE_KEY` is not set, the SDK's Application Default Credentials lookup uses `GOOGLE_APPLICATION_CREDENTIALS`. Keep the account limited to the needed project and rotate the key if it may have been exposed.

## Producer and reviewer credential format

Both maps support multiple key IDs per identity so keys can be rotated without downtime:

```json
{
  "cycling-club-manager": {
    "key-2026-01": "a-long-random-producer-secret"
  }
}
```

```json
{
  "audit-reviewer": {
    "key-2026-01": "a-different-long-random-reviewer-secret"
  }
}
```

For each identity, add a new key ID, update the client, then remove the old key after requests use the new one. Inject secrets from Render's secret environment settings rather than source files.

## API endpoints

### Health and signing keys

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `GET /v1/health/live` | None | Process is responding. |
| `GET /v1/health/ready` | None | Firestore can be queried. |
| `GET /v1/keys` | None | Returns receipt public keys and the current key ID. |

Health responses do not disclose configuration. Public keys are not secret, but clients should pin the expected key independently rather than blindly trusting a key downloaded from the same endpoint they are trying to verify.

### Producer endpoints

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/events` | Producer HMAC | Submit a bounded batch. |
| `GET /v1/receipts/{receiptId}` | Producer HMAC | Retrieve a receipt owned by that producer. |

Example ingestion body:

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

`eventType` uses lowercase dotted names. `outcome` is `success`, `failure`, `denied`, or `unknown`. `actor`, `target`, `correlationId`, `reasonCode`, and `metadata` are optional. Unknown fields are rejected. A first accepted batch returns `201`; a retry with the same `batchId` and same content returns the original signed receipt with `200`. Use a new nonce and signature for every retry. Reusing a batch ID with different content, or reusing an event ID in another batch, returns `409`.

The receipt includes its event IDs, batch digest, sequence range, chain hashes, acceptance time, and Ed25519 signature. It is only a durable receipt from this service; it does not prove independent custody from a privileged Firestore administrator.

### Reviewer endpoints

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `GET /v1/audit/events` | Reviewer HMAC | Search one producer's events. |
| `GET /v1/audit/events/{producerId}/{eventId}` | Reviewer HMAC | Read one event. |
| `POST /v1/audit/verify` | Reviewer HMAC | Verify a batch's receipt signature and stored event chain. |

Search requires `producerId`. Optional parameters are `eventType`, `outcome`, `actorId`, `targetId`, `from`, `to`, `limit` (1–100; default 50), and `pageToken`. Use at most one of `eventType`, `outcome`, `actorId`, and `targetId` per search. `from` and `to` are ISO date values and filter by event occurrence time. Continue pagination by passing back the returned `nextPageToken`.

Example:

```text
GET /v1/audit/events?producerId=cycling-club-manager&eventType=auth.login_success&from=2026-10-01T00%3A00%3A00Z&limit=50
```

Verification body:

```json
{
  "producerId": "cycling-club-manager",
  "batchId": "outbox-batch-01JAZ8D4P7F1"
}
```

Verification reports `receiptSignature`, `batchMatchesReceipt`, `eventChain`, and `chainHead` checks. A valid result confirms the Firestore data matches the signed receipt and chain for that batch. It cannot detect a coordinated rewrite of the database and signing key.

Successful reviewer searches, event reads, and verification calls are written to `reviewerAccessLogs`. Reviewer permissions currently apply to all producers; add narrower reviewer-to-producer authorization before supporting multiple independent customers with different reviewer scopes.

## HMAC request signing

Authenticated requests use these headers:

- `X-Producer-Id` for producers or `X-Reviewer-Id` for reviewers.
- `X-Key-Id` for the configured key ID.
- `X-Timestamp`: Unix time in seconds.
- `X-Nonce`: fresh random 16–128 character value using letters, digits, `_`, or `-`.
- `X-Signature`: hex HMAC-SHA256.

Sign the exact UTF-8 request body (empty for GET requests) with this five-line message and no final newline:

```text
HTTP_METHOD
PATH_AND_QUERY
TIMESTAMP
NONCE
RAW_BODY
```

The server checks the timestamp window, compares signatures in constant time, and records used nonces to reject replay. Include query parameters exactly as sent when signing a search request. Use HTTPS outside local development.

Node.js signing helper:

```ts
import { createHmac, randomBytes } from "node:crypto";

async function signedRequest({
  baseUrl, path, method, identityHeader, identityId, keyId, secret, body = ""
}: {
  baseUrl: string; path: string; method: string;
  identityHeader: "x-producer-id" | "x-reviewer-id"; identityId: string;
  keyId: string; secret: string; body?: string;
}) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(24).toString("base64url");
  const message = [method.toUpperCase(), path, timestamp, nonce, body].join("\n");
  const signature = createHmac("sha256", secret).update(message, "utf8").digest("hex");
  return fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      [identityHeader]: identityId,
      "x-key-id": keyId,
      "x-timestamp": timestamp,
      "x-nonce": nonce,
      "x-signature": signature,
      ...(body ? { "content-type": "application/json" } : {})
    },
    ...(body ? { body } : {})
  });
}
```

Use `x-producer-id` plus the producer secret for `/events` and `/receipts`; use `x-reviewer-id` plus the reviewer secret for `/audit/*`.

## Firestore collections and indexes

- `auditEvents`: accepted event payloads, producer sequence, digest, and chain links.
- `ingestionBatches`: batch idempotency record and chain range.
- `auditReceipts`: signed receipts.
- `chainHeads`: latest sequence and chain hash per producer.
- `requestNonces`: replay protection.
- `reviewerAccessLogs`: successful reviewer searches, reads, and verification actions.

Deploy the indexes in `firestore.indexes.json`. Configure a TTL policy on `requestNonces.expiresAt` (collection group `requestNonces`) so expired replay records are eventually removed. TTL deletion is asynchronous; request timestamps are separately checked. Do not enable TTL on audit events, batches, receipts, chain heads, or reviewer logs until retention and archival requirements are defined.

## Before production use

- Use HTTPS and secrets management; do not put service-account JSON, producer keys, or signing keys in Git.
- Limit Firebase service-account IAM permissions and use a separate project/account for the audit service. Never reuse a producer app's broad admin key if a dedicated identity is available.
- Configure a shared rate-limit store before running multiple service instances; the included limiter is in-memory.
- Monitor rejected signatures, delivery failures, storage availability, and integrity verification failures.
- Connect a producer's transactional outbox only when it retries stable batch IDs, verifies signed receipts, and reconciles receipts after timeouts.
- Add independently administered immutable archive/checkpoints and key custody before claiming strong tamper-resistant audit evidence.
