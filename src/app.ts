import express, { type ErrorRequestHandler } from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { config } from "./config.js";
import { db } from "./firebase.js";
import { HttpError } from "./lib/http-error.js";
import { createEventsRouter } from "./routes/events.js";
import { createAuditReviewRouter } from "./routes/audit-review.js";
import { IngestService } from "./services/ingest-service.js";
import { getReceiptPublicKeys } from "./services/receipt-signing.js";

const app = express();
const service = new IngestService(db);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({
  limit: config.MAX_EVENT_BODY_BYTES,
  strict: true,
  verify: (req, _res, buffer) => {
    (req as import("express").Request).rawBody = Buffer.from(buffer);
  },
}));

app.get("/v1/health/live", (_req, res) => res.json({ status: "ok" }));
app.get("/v1/health/ready", async (_req, res) => {
  try {
    await db.collection("_health").doc("ready").get();
    res.json({ status: "ready" });
  } catch (err){
    console.log(err)
    res.status(503).json({ status: "unavailable" });
  }
});
app.get("/v1/keys", (_req, res) => res.json(getReceiptPublicKeys()));

app.use("/v1", rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  limit: config.RATE_LIMIT_MAX,
  standardHeaders: "draft-8",
  legacyHeaders: false,
}));
app.use("/v1", createEventsRouter(service));
app.use("/v1", createAuditReviewRouter(service));

app.use((_req, res) => res.status(404).json({ error: { code: "NOT_FOUND", message: "Route not found." } }));

const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  if (error instanceof HttpError) {
    res.status(error.status).json({ error: { code: error.code, message: error.message } });
    return;
  }
  if (error?.type === "entity.too.large") {
    res.status(413).json({ error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds the configured limit." } });
    return;
  }
  if (error instanceof SyntaxError && "body" in error) {
    res.status(400).json({ error: { code: "INVALID_JSON", message: "Request body must be valid JSON." } });
    return;
  }
  console.error("Unhandled request error", error);
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed." } });
};
app.use(errorHandler);

export default app;
