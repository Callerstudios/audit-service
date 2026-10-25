import type { NextFunction, Request, Response } from "express";
import { Timestamp } from "firebase-admin/firestore";
import { config } from "../config.js";
import { db } from "../firebase.js";
import { hmacSha256, safeHexEqual, sha256 } from "../lib/crypto.js";
import { HttpError } from "../lib/http-error.js";

export async function authenticateReviewer(req: Request, _res: Response, next: NextFunction) {
  try {
    const reviewerId = req.header("x-reviewer-id");
    const keyId = req.header("x-key-id");
    const timestampText = req.header("x-timestamp");
    const nonce = req.header("x-nonce");
    const signature = req.header("x-signature");
    const keys = reviewerId ? config.reviewerKeys[reviewerId] : undefined;
    const secret = keyId ? keys?.[keyId] : undefined;

    if (!reviewerId || !keyId || !timestampText || !nonce || !signature || !secret) {
      throw new HttpError(401, "Reviewer authentication failed.", "UNAUTHENTICATED");
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
      throw new HttpError(401, "Reviewer authentication failed.", "UNAUTHENTICATED");
    }
    const timestamp = Number(timestampText);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > config.AUTH_CLOCK_SKEW_SECONDS) {
      throw new HttpError(401, "Request timestamp is outside the allowed time window.", "STALE_REQUEST");
    }

    const rawBody = req.rawBody ?? Buffer.alloc(0);
    const canonical = [req.method.toUpperCase(), req.originalUrl, timestampText, nonce, rawBody.toString("utf8")].join("\n");
    if (!safeHexEqual(signature, hmacSha256(secret, canonical))) {
      throw new HttpError(401, "Reviewer authentication failed.", "UNAUTHENTICATED");
    }

    const nonceId = sha256(`reviewer:${reviewerId}:${keyId}:${nonce}`);
    const nonceRef = db.collection("requestNonces").doc(nonceId);
    await db.runTransaction(async (transaction) => {
      const existing = await transaction.get(nonceRef);
      if (existing.exists) throw new HttpError(409, "This signed request has already been used.", "REPLAYED_REQUEST");
      transaction.create(nonceRef, {
        principalType: "reviewer",
        principalId: reviewerId,
        keyId,
        createdAt: Timestamp.now(),
        expiresAt: Timestamp.fromMillis(Date.now() + config.NONCE_TTL_SECONDS * 1000),
      });
    });

    req.reviewer = { id: reviewerId, keyId };
    next();
  } catch (error) {
    next(error);
  }
}
