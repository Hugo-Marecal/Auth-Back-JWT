import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

export const isValidToken = (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    const decodedToken = jwt.verify(token, process.env.JWT_PRIVATE_KEY || 'sshhh');
    if (!decodedToken) {
      res.status(401);
      res.json({ errMessage: 'Token not valid' });
      return;
    }

    res.status(200);
    res.json({ valid: true });
  } catch (error) {
    console.error(error);
    res.status(400);
    res.json({ errMessage: 'Invalid or expired token' });
  }
};
