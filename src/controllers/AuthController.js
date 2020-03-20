import { body, validationResult, sanitizeBody } from "express-validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

import UserModel from "../models/UserModel";

//helper file to prepare responses.
import apiResponse from "../helpers/apiResponse";
import { randomNumber } from "../helpers/utility";

import mailer from "../helpers/mailer";
import { constants } from "../helpers/constants";


dotenv.config();

/**
 * User registration.
 *
 * @param {string}      firstName
 * @param {string}      lastName
 * @param {string}      email
 * @param {string}      password
 *
 * @returns {Object}
 */
export const register = [
	// Validate fields.
	body("firstName").isLength({ min: 1 }).trim().withMessage("First name must be specified.")
		.isAlphanumeric().withMessage("First name has non-alphanumeric characters."),
	body("lastName").isLength({ min: 1 }).trim().withMessage("Last name must be specified.")
		.isAlphanumeric().withMessage("Last name has non-alphanumeric characters."),
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").custom((value) => {
			return UserModel.findOne({ email: value }).then((user) => {
				if (user) {
					return Promise.reject("E-mail already in use");
				}
			});
		}),
	body("password").isLength({ min: 6 }).trim().withMessage("Password must be 6 characters or greater."),
	// Sanitize fields.
	sanitizeBody("firstName").escape(),
	sanitizeBody("lastName").escape(),
	sanitizeBody("email").escape(),
	sanitizeBody("password").escape(),
	// Process request after validation and sanitization.
	(req, res) => {
		try {
			// Extract the validation errors from a request.
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				// Display sanitized values/errors messages.
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				//hash input password
				bcrypt.hash(req.body.password, 10, (err, hash) => {
					// generate OTP for confirmation
					let otp = randomNumber(4);
					// Create User object with escaped and trimmed data
					const user = new UserModel(
						{
							firstName: req.body.firstName,
							lastName: req.body.lastName,
							email: req.body.email,
							password: hash,
							confirmOTP: otp
						}
					);
					// Html email body
					let html = "<p>Please Confirm your Account.</p><p>OTP: " + otp + "</p>";
					// Send confirmation email
					mailer.send(
						constants.confirmEmails.from,
						req.body.email,
						"Confirm Account",
						html
					).then(() => {
						// Save user.
						user.save((err) => {
							if (err) { return apiResponse.errorResponse(res, err); }
							let userData = {
								_id: user._id,
								firstName: user.firstName,
								lastName: user.lastName,
								email: user.email
							};
							return apiResponse.successResponseWithData(res, "Registration Success.", userData);
						});
					}).catch(err => {
						console.log(err);
						return apiResponse.errorResponse(res, err);
					});
				});
			}
		} catch (err) {
			//throw error in json response with status 500.
			return apiResponse.errorResponse(res, err);
		}
	}];

/**
 * User login.
 *
 * @param {string}      email
 * @param {string}      password
 *
 * @returns {Object}
 */
export const login = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	body("password").isLength({ min: 1 }).trim().withMessage("Password must be specified."),
	sanitizeBody("email").escape(),
	sanitizeBody("password").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				UserModel.findOne({ email: req.body.email }).then(user => {
					if (user) {
						//Compare given password with db's hash.
						bcrypt.compare(req.body.password, user.password, (err, same) => {
							if (same) {
								//Check account confirmation.
								if (user.isConfirmed) {
									// Check User's account active or not.
									if (user.status) {
										let userData = {
											_id: user._id,
											firstName: user.firstName,
											lastName: user.lastName,
											email: user.email,
										};
										//Prepare JWT token for authentication
										const jwtPayload = userData;
										const jwtData = {
											expiresIn: process.env.JWT_TIMEOUT_DURATION,
										};
										const secret = process.env.JWT_SECRET;
										//Generated JWT token with Payload and secret.
										userData.token = jwt.sign(jwtPayload, secret, jwtData);
										return apiResponse.successResponseWithData(res, "Login Success.", userData);
									} else {
										return apiResponse.unauthorizedResponse(res, "Account is not active. Please contact admin.");
									}
								} else {
									return apiResponse.unauthorizedResponse(res, "Account is not confirmed. Please confirm your account.");
								}
							} else {
								return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
							}
						});
					} else {
						return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
					}
				});
			}
		} catch (err) {
			return apiResponse.errorResponse(res, err);
		}
	}];

/**
 * Verify Confirm otp.
 *
 * @param {string}      email
 * @param {string}      otp
 *
 * @returns {Object}
 */
export const verifyConfirm = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	body("otp").isLength({ min: 1 }).trim().withMessage("OTP must be specified."),
	sanitizeBody("email").escape(),
	sanitizeBody("otp").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				const query = { email: req.body.email };
				UserModel.findOne(query).then(user => {
					if (user) {
						//Check already confirm or not.
						if (!user.isConfirmed) {
							//Check account confirmation.
							if (user.confirmOTP == req.body.otp) {
								//Update user as confirmed
								UserModel.findOneAndUpdate(query, {
									isConfirmed: 1,
									confirmOTP: null
								}).catch(err => {
									return apiResponse.errorResponse(res, err);
								});
								return apiResponse.successResponse(res, "Account confirmed success.");
							} else {
								return apiResponse.unauthorizedResponse(res, "Otp does not match");
							}
						} else {
							return apiResponse.unauthorizedResponse(res, "Account already confirmed.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Specified email not found.");
					}
				});
			}
		} catch (err) {
			return apiResponse.errorResponse(res, err);
		}
	}];

/**
 * Resend Confirm otp.
 *
 * @param {string}      email
 *
 * @returns {Object}
 */
export const resendConfirmOtp = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	sanitizeBody("email").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				const query = { email: req.body.email };
				UserModel.findOne(query).then(user => {
					if (user) {
						//Check already confirm or not.
						if (!user.isConfirmed) {
							// Generate otp
							let otp = randomNumber(4);
							// Html email body
							let html = "<p>Please Confirm your Account.</p><p>OTP: " + otp + "</p>";
							// Send confirmation email
							mailer.send(
								constants.confirmEmails.from,
								req.body.email,
								"Confirm Account",
								html
							).then(() => {
								user.isConfirmed = 0;
								user.confirmOTP = otp;
								// Save user.
								user.save((err) => {
									if (err) { return apiResponse.errorResponse(res, err); }
									return apiResponse.successResponse(res, "Confirm otp sent.");
								});
							});
						} else {
							return apiResponse.unauthorizedResponse(res, "Account already confirmed.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Specified email not found.");
					}
				});
			}
		} catch (err) {
			return apiResponse.errorResponse(res, err);
		}
	}];