import { Request, Response } from 'express';
import { CreateUserRequest, User } from '../requestExternsions';
import { sendEmail } from '../utils/sendEmail';
import bcrypt from 'bcrypt';
import prisma from '../dbClient';
import jwt from 'jsonwebtoken';

export const createUser = async (req: CreateUserRequest, res: Response) => {
  try {
    const { email, username, password, confirmPassword } = req.body;

    if (!email || !username || !password || !confirmPassword) {
      res.status(401);
      res.json({ errMessage: 'Please complete all fields' });
      return;
    }

    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailRegex.test(email)) {
      res.status(401);
      res.json({ errMessage: 'Email not valid' });
      return;
    }

    const alreadyExistingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (alreadyExistingUser) {
      res.status(401);
      res.json({ errMessage: 'This email is already use' });
      return;
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      res.status(401);
      res.json({
        errMessage:
          'The password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character and have a minimum length of 8 characters.',
      });
      return;
    }

    if (password !== confirmPassword) {
      res.status(401);
      res.json({ errMessage: "Passwords don't match" });
      return;
    }

    const numberSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS || '7', 10);
    const hashedPassword = await bcrypt.hash(password, numberSaltRounds);

    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    if (!newUser) {
      res.status(401);
      res.json({ errMessage: 'Creation failed' });
      return;
    }

    const newVerifyToken = await prisma.token.create({
      data: {
        token: jwt.sign({ id: newUser.id }, process.env.JWT_PRIVATE_KEY || 'sshhh', { expiresIn: '1h' }),
        userId: newUser.id,
      },
    });

    if (!newVerifyToken) {
      res.status(401);
      res.json({ errMessage: 'Creation failed' });
      return;
    }

    if (newVerifyToken.token) {
      await sendEmail(email, newVerifyToken.token);
    }

    res.json({ successMessage: 'Account created, please verify your email with the link sent to you' });
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};

export const loginUser = async (req: CreateUserRequest, res: Response) => {
  try {
    const { email, password } = req.body;

    const user: User | null = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      res.status(401);
      res.json({ errMessage: 'Wrong email/password combination' });
      return;
    }

    if (!user.verify) {
      res.status(401);
      res.json({ errMessage: 'Please verify your email' });
      return;
    }

    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      res.status(401);
      res.json({ errMessage: 'Wrong email/password combination' });
      return;
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_PRIVATE_KEY || 'sshhh', { expiresIn: '24h' });

    res.status(201);
    res.json({ token, successMessage: 'Your are connected' });
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};

export const logoutUser = (req: CreateUserRequest, res: Response) => {
  res.clearCookie('token');
  res.status(200);
  res.json({ successMessage: 'Good Bye' });
};

export const getAccount = async (req: Request, res: Response) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).json({ errorMessage: 'Unauthorized' });
    }

    const { id } = user;

    const userInfo: User | null = await prisma.user.findUnique({
      where: {
        id,
      },
    });

    if (!userInfo) {
      return res.status(401).json({ errorMessage: 'User not found' });
    }

    res.status(200);
    res.json({ id, username: userInfo.username, successMessage: 'You are connected' });
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;

    if (!token) {
      res.status(401);
      res.json({ errMessage: 'Token not valid' });
      return;
    }

    const decodedToken = jwt.verify(token, process.env.JWT_PRIVATE_KEY || 'sshhh');

    if (!decodedToken) {
      res.status(401);
      res.json({ errMessage: 'Token not valid' });
      return;
    }

    const verifyUser = await prisma.user.update({
      where: {
        id: (decodedToken as jwt.JwtPayload).id,
      },
      data: {
        verify: true,
      },
    });

    if (!verifyUser) {
      res.status(401);
      res.json({ errMessage: 'Verification failed' });
      return;
    }

    res.redirect('http://localhost:5173/login?successMessage=Email%20verified%20successfully,%20please%20login');
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};
