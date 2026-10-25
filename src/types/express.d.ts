import "express-serve-static-core";

declare module "express-serve-static-core" {
  interface Request {
    rawBody?: Buffer;
    producer?: {
      id: string;
      keyId: string;
    };
    reviewer?: {
      id: string;
      keyId: string;
    };
  }
}
