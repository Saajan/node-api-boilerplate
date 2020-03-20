import jwt from "express-jwt";
import dotenv from "dotenv";

dotenv.config();

const secret = process.env.JWT_SECRET;

export const authenticate = jwt({
	secret: secret
});
