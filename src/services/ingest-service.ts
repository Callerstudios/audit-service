import { FieldValue, Timestamp, type Firestore } from "firebase-admin/firestore";
import type { AuditEventInput, IngestRequest } from "../domain/audit-event.js";
import { canonicalJson, newId, sha256 } from "../lib/crypto.js";
import { HttpError } from "../lib/http-error.js";

export interface AuditReceipt {
  receiptId: string;
  producerId: string;
  batchId: string;
  eventIds: string[];
  digest: string;
  acceptedAt: string;
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
    acceptedAt: (data.acceptedAt as Timestamp).toDate().toISOString(),
  };
}

export class IngestService {
  constructor(private readonly firestore: Firestore) {}

  async ingest(producerId: string, request: IngestRequest): Promise<{ receipt: AuditReceipt; duplicate: boolean }> {
    const digest = sha256(canonicalJson(request));
    const batchRef = this.firestore.collection("ingestionBatches").doc(scopedDocId(producerId, request.batchId));
    const eventRefs = request.events.map((event) => this.firestore.collection("auditEvents").doc(scopedDocId(producerId, event.eventId)));
    const receiptId = newId();
    const receiptRef = this.firestore.collection("auditReceipts").doc(receiptId);

    const result = await this.firestore.runTransaction(async (transaction) => {
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

      const existingEvents = await transaction.getAll(...eventRefs);
      if (existingEvents.some((snapshot) => snapshot.exists)) {
        throw new HttpError(409, "An eventId was already accepted. Retry the original batchId for idempotent delivery.", "EVENT_ALREADY_ACCEPTED");
      }

      const now = Timestamp.now();
      const receipt: AuditReceipt = {
        receiptId,
        producerId,
        batchId: request.batchId,
        eventIds: request.events.map((event) => event.eventId),
        digest,
        acceptedAt: now.toDate().toISOString(),
      };
      request.events.forEach((event: AuditEventInput, index) => {
        transaction.create(eventRefs[index]!, {
          ...event,
          schemaVersion: request.schemaVersion,
          producerId,
          batchId: request.batchId,
          digest: sha256(canonicalJson(event)),
          acceptedAt: now,
        });
      });
      transaction.create(batchRef, {
        producerId,
        batchId: request.batchId,
        receiptId,
        eventIds: receipt.eventIds,
        digest,
        acceptedAt: now,
      });
      transaction.create(receiptRef, {
        ...receipt,
        acceptedAt: now,
        createdAt: FieldValue.serverTimestamp(),
      });
      return { receipt, duplicate: false };
    });

    return result;
  }

  async getReceipt(producerId: string, receiptId: string): Promise<AuditReceipt> {
    const snapshot = await this.firestore.collection("auditReceipts").doc(receiptId).get();
    if (!snapshot.exists || snapshot.get("producerId") !== producerId) {
      throw new HttpError(404, "Receipt not found.", "RECEIPT_NOT_FOUND");
    }
    return mapReceipt(snapshot.data()!);
  }
}
