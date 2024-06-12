import { Request } from 'express';

// Interface for CreateUserRequest
export interface CreateUserRequest extends Request {
  body: {
    email: string;
    username: string;
    password: string;
    confirmPassword: string;
  };
}

// Interface User
export interface User {
  id: string;
  createdAt: Date;
  email: string;
  username: string;
  password: string;
  verify: boolean;
}
