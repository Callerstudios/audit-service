import { Router } from "express";
import { z } from "zod";
import { HttpError } from "../lib/http-error.js";
import { authenticateReviewer } from "../middleware/reviewer-auth.js";
import { IngestService } from "../services/ingest-service.js";

function queryString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(
      400,
      `${name} must be a single non-empty string.`,
      "INVALID_SEARCH",
    );
  }
  return value;
}

function queryDate(value: unknown, name: string): Date | undefined {
  const text = queryString(value, name);
  if (text === undefined) return undefined;
  const date = new Date(text);
  if (Number.isNaN(date.getTime()))
    throw new HttpError(400, `${name} must be a valid date.`, "INVALID_SEARCH");
  return date;
}

export function createAuditReviewRouter(service: IngestService) {
  const router = Router();

  router.get("/audit/events", authenticateReviewer, async (req, res, next) => {
    try {
      const producerId = queryString(req.query.producerId, "producerId");
      if (!producerId)
        throw new HttpError(400, "producerId is required.", "INVALID_SEARCH");
      const eventType = queryString(req.query.eventType, "eventType");
      const outcome = queryString(req.query.outcome, "outcome");
      const actorId = queryString(req.query.actorId, "actorId");
      const targetId = queryString(req.query.targetId, "targetId");
      const from = queryDate(req.query.from, "from");
      const to = queryDate(req.query.to, "to");
      if (from && to && from > to)
        throw new HttpError(
          400,
          "from must be earlier than or equal to to.",
          "INVALID_SEARCH",
        );
      const rawLimit =
        req.query.limit === undefined
          ? "50"
          : queryString(req.query.limit, "limit")!;
      const limit = Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        throw new HttpError(
          400,
          "limit must be an integer from 1 to 100.",
          "INVALID_SEARCH",
        );
      }
      const pageToken = queryString(req.query.pageToken, "pageToken");

      const result = await service.searchEvents({
        producerId,
        eventType,
        outcome,
        actorId,
        targetId,
        from,
        to,
        limit,
        pageToken,
      });
      await service.logReviewerAccess(req.reviewer!.id, "audit.events.search", {
        producerId,
        eventType,
        outcome,
        actorId,
        targetId,
        from: from?.toISOString(),
        to: to?.toISOString(),
        returnedCount: result.events.length,
      });
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  router.get(
    "/audit/events/:producerId/:eventId",
    authenticateReviewer,
    async (req, res, next) => {
      try {
        const producerId = requiredPathParam(
          req.params.producerId,
          "producerId",
        );
        const eventId = requiredPathParam(req.params.eventId, "eventId");

        const event = await service.getEvent(producerId, eventId);

        await service.logReviewerAccess(req.reviewer!.id, "audit.event.read", {
          producerId,
          eventId,
        });

        res.json({ event });
      } catch (error) {
        next(error);
      }
    },
  );

  const verifyRequestSchema = z
    .object({
      producerId: z.string().min(1).max(160),
      batchId: z.string().min(1).max(160),
    })
    .strict();

  router.post("/audit/verify", authenticateReviewer, async (req, res, next) => {
    try {
      const parsed = verifyRequestSchema.safeParse(req.body);
      if (!parsed.success)
        throw new HttpError(
          400,
          "producerId and batchId are required.",
          "INVALID_VERIFY_REQUEST",
        );
      const result = await service.verifyBatch(
        parsed.data.producerId,
        parsed.data.batchId,
      );
      await service.logReviewerAccess(
        req.reviewer!.id,
        "audit.batch.verify",
        parsed.data,
      );
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  return router;
}
function requiredPathParam(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(
      400,
      `${name} must be a single non-empty string.`,
      "INVALID_SEARCH",
    );
  }

  return value;
}