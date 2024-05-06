import * as dotenv from "dotenv";

dotenv.config();

import zod from "zod";

import * as jose from "jose";

import cryptApi from "../helpers/cryptApi.js";

import pool from "../config/dbConfig.js";

class AuthUsersController {
    constructor() {

        this.sql = pool.promise();
    }

    authUsersApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15 * 60 * 60)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authAssignmentsApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_ASSIGNMENTS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authBacklinksApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_BACKLINKS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authFreelancersApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_FREELANCERS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authFreelancersApiByFreelancer = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM freelancers WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_FREELANCERS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authClientsApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_CLIENTS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authClientsApiByClient = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM clients WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_CLIENTS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authAssignmentsEmailApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_ASSIGNMENTS_EMAIL_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authLogiccirclecoEmailsApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_ASSIGNMENTS_APP_EMAIL_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authLogiccirclenetEmailsApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_LOGICCIRCLENET_EMAILS_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    authTestApi = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id }

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const result = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_TEST_API);

            const jwtToken = await new jose.SignJWT({ data: result })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 15)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message}` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

    test = async (req, res) => {

        try {

            console.log(req.body)

            const email = req.body.email;

            console.log(email)

            const [rows] = await this.sql.query("SELECT * FROM users WHERE email = ?", [email]);

            return res.json({ error: false, data: rows });

        } catch (error) {

            console.log(error);

            if (error.issues) {

                const zodErrorData = JSON.parse(error.message).map((errorMessage) => {

                    if (errorMessage.message) return { message: `"${errorMessage?.path}" is ${errorMessage?.message} ` };

                })

                return res.json({ error: true, data: zodErrorData[0]?.message });

            } else {

                console.log(error.message.fields);

                if (error.message?.fields) return res.json({ error: true, data: error.message.fields?.message });

                if (error.message.fields) return res.json({ error: true, data: error.message.fields?.message });

                return res.json({ error: true, data: error.message });

            }

        }

    }

}

export default AuthUsersController