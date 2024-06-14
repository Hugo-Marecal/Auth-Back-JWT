import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

export const isAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const bearerToken = req.headers.authorization;

    if (!bearerToken || !bearerToken.startsWith('Bearer ')) {
      res.status(401);
      res.json({ errMessage: 'Not authorized' });
      return;
    }

    // I don´t need the first element of the array so i use a comma
    const [, token] = bearerToken.split(' ');

    // const token = req.cookies.token;
    if (!token) {
      res.status(401);
      res.json({ errMessage: 'Not authorized' });
      return;
    }

    const decodedToken = jwt.verify(token, process.env.JWT_PRIVATE_KEY || 'sshhh');
    if (!decodedToken) {
      res.status(401);
      res.json({ errMessage: 'Not authorized' });
      return;
    }

    req.user = { id: (decodedToken as JwtPayload).id };
    next();
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json(error);
  }
};
