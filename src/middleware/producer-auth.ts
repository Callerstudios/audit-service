import type { NextFunction, Request, Response } from "express";
import { Timestamp } from "firebase-admin/firestore";
import { config } from "../config.js";
import { hmacSha256, safeHexEqual, sha256 } from "../lib/crypto.js";
import { HttpError } from "../lib/http-error.js";
import { db } from "../firebase.js";

export async function authenticateProducer(req: Request, _res: Response, next: NextFunction) {
  try {
    const producerId = req.header("x-producer-id");
    const keyId = req.header("x-key-id");
    const timestampText = req.header("x-timestamp");
    const nonce = req.header("x-nonce");
    const signature = req.header("x-signature");
    const keys = producerId ? config.producerKeys[producerId] : undefined;
    const secret = keyId ? keys?.[keyId] : undefined;

    if (!producerId || !keyId || !timestampText || !nonce || !signature || !secret) {
      throw new HttpError(401, "Producer authentication failed.", "UNAUTHENTICATED");
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
      throw new HttpError(401, "Producer authentication failed.", "UNAUTHENTICATED");
    }
    const timestamp = Number(timestampText);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > config.AUTH_CLOCK_SKEW_SECONDS) {
      throw new HttpError(401, "Request timestamp is outside the allowed time window.", "STALE_REQUEST");
    }

    const pathAndQuery = req.originalUrl;
    const rawBody = req.rawBody ?? Buffer.alloc(0);
    const canonical = [req.method.toUpperCase(), pathAndQuery, timestampText, nonce, rawBody.toString("utf8")].join("\n");
    if (!safeHexEqual(signature, hmacSha256(secret, canonical))) {
      throw new HttpError(401, "Producer authentication failed.", "UNAUTHENTICATED");
    }

    const nonceId = sha256(`${producerId}:${keyId}:${nonce}`);
    const nonceRef = db.collection("requestNonces").doc(nonceId);
    const expiresAt = Timestamp.fromMillis(Date.now() + config.NONCE_TTL_SECONDS * 1000);
    await db.runTransaction(async (transaction) => {
      const existing = await transaction.get(nonceRef);
      if (existing.exists) {
        throw new HttpError(409, "This signed request has already been used.", "REPLAYED_REQUEST");
      }
      transaction.create(nonceRef, { producerId, keyId, createdAt: Timestamp.now(), expiresAt });
    });

    req.producer = { id: producerId, keyId };
    next();
  } catch (error) {
    next(error);
  }
}
