import jwt from 'jsonwebtoken';

export const isAuth = async (req: any, res: any, next: any) => {
  try {
    const bearerToken = req.headers.authorization;

    if (!bearerToken || !bearerToken.startsWith('Bearer ')) {
      res.status(401);
      res.json({ errMessage: 'Not authorized' });
    }

    // I don´t need the first element of the array so i use a comma
    const [, token] = bearerToken.split(' ');

    const user = jwt.verify(token, process.env.JWT_PRIVATE_KEY || 'sshhh');
    if (!user) {
      res.status(401);
      res.json({ errMessage: 'Not authorized' });
    }

    req.user = user;
    console.log(user);
    next();
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json(error);
  }
};
