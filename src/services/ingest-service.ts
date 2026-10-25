import { FieldPath, FieldValue, Timestamp, type Firestore } from "firebase-admin/firestore";
import type { AuditEventInput, IngestRequest } from "../domain/audit-event.js";
import { canonicalJson, newId, sha256 } from "../lib/crypto.js";
import { HttpError } from "../lib/http-error.js";
import { signReceipt, verifyReceipt, type ReceiptSignature } from "./receipt-signing.js";

const GENESIS_HASH = "0".repeat(64);

export interface AuditReceipt {
  receiptId: string;
  producerId: string;
  batchId: string;
  eventIds: string[];
  digest: string;
  acceptedAt: string;
  chain: {
    firstSequence: number;
    lastSequence: number;
    previousHash: string;
    headHash: string;
  };
  signature: ReceiptSignature;
}

function scopedDocId(producerId: string, id: string): string {
  return sha256(`${producerId}:${id}`);
}

function mapReceipt(data: FirebaseFirestore.DocumentData): AuditReceipt {
  return {
    receiptId: data.receiptId,
    producerId: data.producerId,
    batchId: data.batchId,
    eventIds: data.eventIds,
    digest: data.digest,
    acceptedAt: data.acceptedAtIso ?? (data.acceptedAt as Timestamp).toDate().toISOString(),
    chain: data.chain,
    signature: data.signature,
  };
}

function eventChainHash(producerId: string, sequence: number, previousHash: string, eventDigest: string): string {
  return sha256(["audit-chain-v1", producerId, sequence, previousHash, eventDigest].join("\n"));
}

export class IngestService {
  constructor(private readonly firestore: Firestore) {}

  async ingest(producerId: string, request: IngestRequest): Promise<{ receipt: AuditReceipt; duplicate: boolean }> {
    const digest = sha256(canonicalJson(request));
    const batchRef = this.firestore.collection("ingestionBatches").doc(scopedDocId(producerId, request.batchId));
    const eventRefs = request.events.map((event) => this.firestore.collection("auditEvents").doc(scopedDocId(producerId, event.eventId)));
    const headRef = this.firestore.collection("chainHeads").doc(scopedDocId(producerId, producerId));
    const receiptId = newId();
    const receiptRef = this.firestore.collection("auditReceipts").doc(receiptId);

    return this.firestore.runTransaction(async (transaction) => {
      const batchSnapshot = await transaction.get(batchRef);
      if (batchSnapshot.exists) {
        const existing = batchSnapshot.data()!;
        if (existing.digest !== digest) {
          throw new HttpError(409, "batchId was already accepted with different content.", "IDEMPOTENCY_CONFLICT");
        }
        const existingReceipt = await transaction.get(this.firestore.collection("auditReceipts").doc(existing.receiptId));
        if (!existingReceipt.exists) {
          throw new HttpError(503, "Receipt data is unavailable; contact the service operator.", "RECEIPT_UNAVAILABLE");
        }
        return { receipt: mapReceipt(existingReceipt.data()!), duplicate: true };
      }

      const [existingEvents, headSnapshot] = await Promise.all([
        transaction.getAll(...eventRefs),
        transaction.get(headRef),
      ]);
      if (existingEvents.some((snapshot) => snapshot.exists)) {
        throw new HttpError(409, "An eventId was already accepted. Retry the original batchId for idempotent delivery.", "EVENT_ALREADY_ACCEPTED");
      }

      const head = headSnapshot.data();
      const previousHash = head?.lastHash ?? GENESIS_HASH;
      const previousSequence = head?.lastSequence ?? 0;
      const firstSequence = previousSequence + 1;
      let chainHash = previousHash;
      const now = Timestamp.now();
      const eventRecords = request.events.map((event: AuditEventInput, index) => {
        const sequence = firstSequence + index;
        const eventDigest = sha256(canonicalJson(event));
        const nextHash = eventChainHash(producerId, sequence, chainHash, eventDigest);
        const record = {
          event,
          eventId: event.eventId,
          eventType: event.eventType,
          outcome: event.outcome,
          actorId: event.actor?.id ?? null,
          targetId: event.target?.id ?? null,
          occurredAt: Timestamp.fromDate(new Date(event.occurredAt)),
          schemaVersion: request.schemaVersion,
          producerId,
          batchId: request.batchId,
          sequence,
          eventDigest,
          previousHash: chainHash,
          chainHash: nextHash,
          acceptedAt: now,
        };
        chainHash = nextHash;
        return { ref: eventRefs[index]!, record };
      });

      const unsignedReceipt = {
        receiptId,
        producerId,
        batchId: request.batchId,
        eventIds: request.events.map((event) => event.eventId),
        digest,
        acceptedAt: now.toDate().toISOString(),
        chain: { firstSequence, lastSequence: firstSequence + request.events.length - 1, previousHash, headHash: chainHash },
      };
      const receipt = signReceipt(unsignedReceipt) as AuditReceipt;

      for (const event of eventRecords) transaction.create(event.ref, event.record);
      transaction.create(batchRef, {
        producerId,
        batchId: request.batchId,
        receiptId,
        eventIds: receipt.eventIds,
        digest,
        firstSequence: receipt.chain.firstSequence,
        lastSequence: receipt.chain.lastSequence,
        previousHash: receipt.chain.previousHash,
        chainHead: receipt.chain.headHash,
        acceptedAt: now,
      });
      transaction.create(receiptRef, {
        ...receipt,
        acceptedAt: now,
        acceptedAtIso: receipt.acceptedAt,
        createdAt: FieldValue.serverTimestamp(),
      });
      transaction.set(headRef, {
        producerId,
        lastSequence: receipt.chain.lastSequence,
        lastHash: receipt.chain.headHash,
        updatedAt: now,
      });

      return { receipt, duplicate: false };
    });
  }

  async getReceipt(producerId: string, receiptId: string): Promise<AuditReceipt> {
    const snapshot = await this.firestore.collection("auditReceipts").doc(receiptId).get();
    if (!snapshot.exists || snapshot.get("producerId") !== producerId) {
      throw new HttpError(404, "Receipt not found.", "RECEIPT_NOT_FOUND");
    }
    return mapReceipt(snapshot.data()!);
  }

  async verifyBatch(producerId: string, batchId: string) {
    const batchRef = this.firestore.collection("ingestionBatches").doc(scopedDocId(producerId, batchId));
    const batchSnapshot = await batchRef.get();
    if (!batchSnapshot.exists) throw new HttpError(404, "Batch not found.", "BATCH_NOT_FOUND");
    const batch = batchSnapshot.data()!;
    const receiptSnapshot = await this.firestore.collection("auditReceipts").doc(batch.receiptId).get();
    if (!receiptSnapshot.exists) throw new HttpError(503, "Receipt data is unavailable.", "RECEIPT_UNAVAILABLE");
    const eventRefs = (batch.eventIds as string[]).map((eventId) =>
      this.firestore.collection("auditEvents").doc(scopedDocId(producerId, eventId)));
    const eventSnapshots = await Promise.all(eventRefs.map((ref) => ref.get()));
    const receipt = mapReceipt(receiptSnapshot.data()!);

    let expectedPreviousHash = batch.previousHash as string;
    let expectedSequence = batch.firstSequence as number;
    let eventChainValid = eventSnapshots.length === (batch.eventIds as string[]).length;
    const verifiedEvents: AuditEventInput[] = [];
    for (const snapshot of eventSnapshots) {
      if (!snapshot.exists) {
        eventChainValid = false;
        continue;
      }
      const record = snapshot.data()!;
      verifiedEvents.push(record.event as AuditEventInput);
      const eventDigest = sha256(canonicalJson(record.event));
      const computedHash = eventChainHash(producerId, expectedSequence, expectedPreviousHash, eventDigest);
      if (
        record.producerId !== producerId ||
        record.batchId !== batchId ||
        record.eventId !== record.event?.eventId ||
        record.sequence !== expectedSequence ||
        record.eventDigest !== eventDigest ||
        record.previousHash !== expectedPreviousHash ||
        record.chainHash !== computedHash
      ) {
        eventChainValid = false;
      }
      expectedPreviousHash = record.chainHash;
      expectedSequence += 1;
    }

    const receiptValid = receipt.producerId === producerId && receipt.batchId === batchId && verifyReceipt(receipt as unknown as Record<string, unknown>);
    const payloadDigestValid = verifiedEvents.length === (batch.eventIds as string[]).length &&
      sha256(canonicalJson({ schemaVersion: 1, batchId, events: verifiedEvents })) === batch.digest;
    const batchMatchesReceipt = receipt.receiptId === batch.receiptId && receipt.digest === batch.digest &&
      receipt.eventIds.join("\0") === (batch.eventIds as string[]).join("\0") &&
      receipt.chain.firstSequence === batch.firstSequence && receipt.chain.lastSequence === batch.lastSequence &&
      receipt.chain.previousHash === batch.previousHash && receipt.chain.headHash === batch.chainHead;
    const chainHeadMatches = expectedPreviousHash === batch.chainHead && expectedSequence - 1 === batch.lastSequence;

    return {
      valid: receiptValid && payloadDigestValid && batchMatchesReceipt && eventChainValid && chainHeadMatches,
      checks: { receiptSignature: receiptValid, payloadDigest: payloadDigestValid, batchMatchesReceipt, eventChain: eventChainValid, chainHead: chainHeadMatches },
      receipt,
    };
  }

  async searchEvents(filters: {
    producerId: string;
    eventType?: string;
    outcome?: string;
    actorId?: string;
    targetId?: string;
    from?: Date;
    to?: Date;
    limit: number;
    pageToken?: string;
  }) {
    const queryFilters = [filters.eventType, filters.outcome, filters.actorId, filters.targetId].filter(Boolean);
    if (queryFilters.length > 1) {
      throw new HttpError(400, "Use only one of eventType, outcome, actorId, or targetId per search.", "INVALID_SEARCH");
    }

    let query: FirebaseFirestore.Query = this.firestore.collection("auditEvents")
      .where("producerId", "==", filters.producerId);
    if (filters.eventType) query = query.where("eventType", "==", filters.eventType);
    if (filters.outcome) query = query.where("outcome", "==", filters.outcome);
    if (filters.actorId) query = query.where("actorId", "==", filters.actorId);
    if (filters.targetId) query = query.where("targetId", "==", filters.targetId);
    if (filters.from) query = query.where("occurredAt", ">=", Timestamp.fromDate(filters.from));
    if (filters.to) query = query.where("occurredAt", "<=", Timestamp.fromDate(filters.to));
    query = query.orderBy("occurredAt", "desc").orderBy(FieldPath.documentId(), "desc");

    if (filters.pageToken) {
      let cursorId: string;
      try {
        cursorId = Buffer.from(filters.pageToken, "base64url").toString("utf8");
        if (!/^[a-f0-9]{64}$/.test(cursorId)) throw new Error("Invalid cursor.");
      } catch {
        throw new HttpError(400, "pageToken is invalid.", "INVALID_PAGE_TOKEN");
      }
      const cursor = await this.firestore.collection("auditEvents").doc(cursorId).get();
      if (!cursor.exists || cursor.get("producerId") !== filters.producerId) {
        throw new HttpError(400, "pageToken is invalid.", "INVALID_PAGE_TOKEN");
      }
      query = query.startAfter(cursor);
    }

    const snapshot = await query.limit(filters.limit + 1).get();
    const hasMore = snapshot.docs.length > filters.limit;
    const docs = hasMore ? snapshot.docs.slice(0, filters.limit) : snapshot.docs;
    const events = docs.map((doc) => {
      const data = doc.data();
      return {
        ...data.event,
        producerId: data.producerId,
        batchId: data.batchId,
        sequence: data.sequence,
        eventDigest: data.eventDigest,
        previousHash: data.previousHash,
        chainHash: data.chainHash,
        acceptedAt: (data.acceptedAt as Timestamp).toDate().toISOString(),
      };
    });
    const last = docs.at(-1);
    return {
      events,
      nextPageToken: hasMore && last ? Buffer.from(last.id).toString("base64url") : null,
    };
  }

  async getEvent(producerId: string, eventId: string) {
    const snapshot = await this.firestore.collection("auditEvents").doc(scopedDocId(producerId, eventId)).get();
    if (!snapshot.exists) throw new HttpError(404, "Audit event not found.", "EVENT_NOT_FOUND");
    const data = snapshot.data()!;
    return {
      ...data.event,
      producerId: data.producerId,
      batchId: data.batchId,
      sequence: data.sequence,
      eventDigest: data.eventDigest,
      previousHash: data.previousHash,
      chainHash: data.chainHash,
      acceptedAt: (data.acceptedAt as Timestamp).toDate().toISOString(),
    };
  }

  async logReviewerAccess(reviewerId: string, action: string, details: Record<string, unknown>) {
    const cleanDetails = Object.fromEntries(Object.entries(details).filter(([, value]) => value !== undefined));
    await this.firestore.collection("reviewerAccessLogs").add({
      reviewerId,
      action,
      details: cleanDetails,
      createdAt: FieldValue.serverTimestamp(),
    });
  }
}
