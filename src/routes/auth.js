import express from "express";
import { register, login, verifyConfirm, resendConfirmOtp } from "../controllers/AuthController";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/verify-otp", verifyConfirm);
router.post("/resend-verify-otp", resendConfirmOtp);

export default router;