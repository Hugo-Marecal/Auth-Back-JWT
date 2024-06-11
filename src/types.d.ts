// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { Request } from 'express';

// We extend the Express `Request` interface to include the `user` property.
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
      };
    }
  }
}
