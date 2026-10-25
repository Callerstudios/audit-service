import { Router } from "express";
import { config } from "../config.js";
import { validateIngestBody } from "../domain/audit-event.js";
import { HttpError } from "../lib/http-error.js";
import { authenticateProducer } from "../middleware/producer-auth.js";
import { IngestService } from "../services/ingest-service.js";

export function createEventsRouter(service: IngestService) {
  const router = Router();
  router.use(authenticateProducer);

  router.post("/events", async (req, res, next) => {
    try {
      let payload;
      try {
        payload = validateIngestBody(req.body, config.MAX_EVENTS_PER_BATCH);
      } catch (error) {
        throw new HttpError(400, error instanceof Error ? error.message : "Invalid event payload.", "INVALID_EVENT");
      }
      const result = await service.ingest(req.producer!.id, payload);
      res.status(result.duplicate ? 200 : 201).json(result);
    } catch (error) {
      next(error);
    }
  });

  router.get("/receipts/:receiptId", async (req, res, next) => {
    try {
      const receipt = await service.getReceipt(req.producer!.id, req.params.receiptId);
      res.json({ receipt });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
