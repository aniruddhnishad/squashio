import * as dotenv from "dotenv";

dotenv.config();

import zod from "zod";

import * as jose from "jose";

import bcrypt from "bcrypt";

import pool from "../config/dbConfig.js";

import cryptApi from "../helpers/cryptApi.js";

class UsersController {
    constructor() {

        this.sql = pool.promise();
    }

    checkUser = async (req, res) => {

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

            const checkDataResult = [{
                user_id: rows[0].user_id,
                u_id: rows[0].u_id,
                email: rows[0].email,
                roles: rows[0].roles,
            }];

            return res.json({ error: false, data: checkDataResult });

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

    addSuperAdmin = async (req, res) => {

        try {

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const password = req.body.password ? (typeof req.body.password == "string") ? req.body.password.trim() : req.body.password : req.body.password;

            const roles = req.body.roles;

            const reqBodyData = { email, password, roles }

            const zodObj = zod.object({ email: zod.string().email(), password: zod.string().min(5).max(100), roles: zod.array(zod.string()) });

            zodObj.parse(reqBodyData);

            const hashedPassword = bcrypt.hashSync(password, 10);

            const valueRoles = JSON.stringify(roles.map((role) => role.trim().toUpperCase()));

            const [rows] = await this.sql.query("SELECT * FROM users WHERE email = ?", [email]);

            if (rows.length !== 0) return res.json({ error: true, data: "User already exist!" });

            process.env.TZ = 'Asia/kolkata';

            const date = new Date().getTime();

            const result = await this.sql.query("INSERT INTO users ( u_id, email, password, roles) VALUES ( ?, ?, ?, ?)", [date, email, hashedPassword, valueRoles]);

            if (result[0].affectedRows === 0) return res.json({ error: true, data: "Unable to add user!" });

            return res.json({ error: false, data: `User registered successfully!` });

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

    register = async (req, res) => {

        try {

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const password = req.body.password ? (typeof req.body.password == "string") ? req.body.password.trim() : req.body.password : req.body.password;

            const roles = req.body.roles;

            const reqBodyData = { email, password, roles }

            const zodObj = zod.object({ email: zod.string().email(), password: zod.string().min(5).max(100), roles: zod.array(zod.string()) });

            zodObj.parse(reqBodyData);

            const hashedPassword = bcrypt.hashSync(password, 10);

            const valueRoles = roles.map((role) => role.trim().toUpperCase());

            if (valueRoles.includes('SUPERADMIN')) return res.json({ error: true, data: `Can not add role "SUPERADMIN"` });

            const [rows] = await this.sql.query("SELECT * FROM users WHERE email = ?", [email]);

            if (rows.length !== 0) return res.json({ error: true, data: "User already exist!" });

            process.env.TZ = 'Asia/kolkata';

            const date = new Date().getTime();

            const result = await this.sql.query("INSERT INTO users( u_id, email, password, roles) VALUES ( ?, ?, ?, ?)", [date, email, hashedPassword, JSON.stringify(valueRoles)]);

            if (result[0].affectedRows === 0) return res.json({ error: true, data: 'Unable to add user!' });

            return res.json({ error: false, data: `User registered successfully!` });

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

    login = async (req, res) => {

        try {

            const ipAddress = req.header('x-forwarded-for') || req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || '0.0.0.0';

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const password = req.body.password ? (typeof req.body.password == "string") ? req.body.password.trim() : req.body.password : req.body.password;

            const reqBodyData = { email, password }

            const zodObj = zod.object({ email: zod.string().email(), password: zod.string().min(5).max(30) });

            zodObj.parse(reqBodyData);

            const [rows] = await this.sql.query(`SELECT * FROM users WHERE email = ?`, [email]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (!bcrypt.compareSync(password, rows[0].password)) return res.json({ error: true, data: "Invalid credentials!" });
            
            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            if (rows[0].first_login_ip == '0.0.0.0' || rows[0].first_login_ip == '') {

                const resultFirstLoginIp = await this.sql.query(`UPDATE users SET first_login_ip = ? WHERE email = ?`, [ipAddress, email]);

                if (resultFirstLoginIp.rowCount === 0) {
                    
                    return res.json({ error: true, data: "Unable to update first_login_ip!" });
                }

            }

            const resultLastLoginIp = await this.sql.query(`UPDATE users SET last_login_ip = ? WHERE email = ?`, [ipAddress, email]);

            if (resultLastLoginIp.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update last_login_ip!" });
            }

            const tokens = rows[0].tokens ? JSON.parse(rows[0].tokens) : [];

            if (tokens.length > 10) {
                
                return res.json({ error: true, data: "You have exceeded maximum login instances!" });
            }

            delete rows[0].password;

            delete rows[0].image;

            delete rows[0].about;

            delete rows[0].contact;

            delete rows[0].first_login_ip;

            delete rows[0].last_login_ip;

            delete rows[0].tokens;

            delete rows[0].allowed_devices;

            delete rows[0].max_allowed_devices;

            delete rows[0].login_instances;

            delete rows[0].allowed_login_instances;

            delete rows[0].created_at;

            delete rows[0].updated_at;

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API);

            const jwtToken = await new jose.SignJWT({ data: rows })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30)
                .sign(secret)

            tokens.push(cryptApi.encrypt(jwtToken))

            const resultTokens = await this.sql.query(`UPDATE users SET tokens = ? WHERE email = ?`, [JSON.stringify(tokens), email]);

            if (resultTokens[0].affectedRows === 0) return res.json({ error: true, data: "Unable to update data!" });
            
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

    switchRole = async (req, res) => {

        try {

            const token = req.token;

            const email = req.email;

            const [rows] = await this.sql.query(`SELECT * FROM users WHERE email = ?`, [email]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const tokens = rows[0].tokens ? JSON.parse(rows[0].tokens) : [];

            const tokensIndex = tokens.indexOf(token);

            if (tokensIndex !== -1) {

                tokens.splice(tokensIndex, 1);
            }

            const resultTokens = await this.sql.query(`UPDATE users SET tokens = ? WHERE email = ?`, [JSON.stringify(tokens), email]);

            if (resultTokens[0].affectedRows === 0) return res.json({ error: true, data: "Unable to update data!" });
            
            delete rows[0].password;

            delete rows[0].image;

            delete rows[0].about;

            delete rows[0].contact;

            delete rows[0].first_login_ip;

            delete rows[0].last_login_ip;

            delete rows[0].tokens;

            delete rows[0].allowed_devices;

            delete rows[0].max_allowed_devices;

            delete rows[0].login_instances;

            delete rows[0].allowed_login_instances;

            delete rows[0].created_at;

            delete rows[0].updated_at;

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API);

            const jwtToken = await new jose.SignJWT({ data: rows })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30)
                .sign(secret)

            tokens.push(cryptApi.encrypt(jwtToken))

            const resultTokensNew = await this.sql.query(`UPDATE users SET tokens = ? WHERE email = ?`, [JSON.stringify(tokens), email]);

            if (resultTokensNew[0].affectedRows === 0) return res.json({ error: true, data: "Unable to update data!" });
            
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

    logout = async (req, res) => {

        try {

            const token = req.token;

            const email = req.email;

            const [rows] = await this.sql.query(`SELECT * FROM users WHERE email = ?`, [email]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const tokens = rows[0].tokens ? JSON.parse(rows[0].tokens) : [];

            const tokensIndex = tokens.indexOf(token);

            if (tokensIndex !== -1) {

                tokens.splice(tokensIndex, 1);
            }

            const resultTokens = await this.sql.query(`UPDATE users SET tokens = ? WHERE email = ?`, [JSON.stringify(tokens), email]);

            if (resultTokens.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Logout successfully!` });

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

    logoutAllDevices = async (req, res) => {

        try {

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const password = req.body.password ? (typeof req.body.password == "string") ? req.body.password.trim() : req.body.password : req.body.password;

            const reqBodyData = { email, password }

            const zodObj = zod.object({ email: zod.string().email(), password: zod.string().min(5).max(30) });

            zodObj.parse(reqBodyData);

            const [rows] = await this.sql.query(`SELECT * FROM users WHERE email = ?`, [email]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (!bcrypt.compareSync(password, rows[0].password)) {
                
                return res.json({ error: true, data: "Invalid credentials!" });
            }

            if (rows[0].status === 0) {
                
                return res.json({ error: true, data: "User account is not active!" });
            }

            if (+rows[0].ban_status === 1 || +rows[0]?.ban_by !== 0) {
                
                return res.json({ error: true, data: "User account is banned!" });
            }

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account marked deleted!" });
            }

            const tokens = rows[0].tokens ? JSON.parse(rows[0].tokens) : [];

            if (tokens.length === 0) {
                
                return res.json({ error: true, data: "There is no login device!" });
            }

            const resultTokens = await this.sql.query(`UPDATE users SET tokens = ? WHERE email = ?`, [JSON.stringify([]), email]);

            if (resultTokens.rowCount == 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Logout all devices successfully!` });

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


    /////////////////////////////////////////////////////////////////////////////////////

    /* Get user/users */

    /////////////////////////////////////////////////////////////////////////////////////

    getUser = async (req, res) => {

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

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });
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

    getUserByApp = async (req, res) => {

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

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (rows[0].status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0].ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0].deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });
            
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

    getUsers = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({ offset: zod.number().int().optional(), limit: zod.number().int().optional() });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
            return res.json({ error: false, data: rows });

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

    getUsersByApp = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({ offset: zod.number().int().optional(), limit: zod.number().int().optional() });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE status = 1 AND ban_status = 0 AND ban_by = 0 AND deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
            return res.json({ error: false, data: rows });

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

    getUsersDataByApp = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({ offset: zod.number().int().optional(), limit: zod.number().int().optional() });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, user_website_data FROM users WHERE assignment_user = 1 ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
            return res.json({ error: false, data: rows });

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

    getAllUsers = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({ offset: zod.number().int().optional(), limit: zod.number().int().optional() });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
            return res.json({ error: false, data: rows });

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

    getUsersByStatus0 = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE status = 0 AND deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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


    getUsersByStatus1 = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE status = 1 AND deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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


    getUsersByBanStatus0 = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE ban_status = 0 AND deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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


    getUsersByBanStatus1 = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE ban_status = 1 AND deleted_at IS NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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

    getUsersByCountry = async (req, res) => {

        try {

            const country = req.body.country ? (typeof req.body.country == "string") ? req.body.country.trim() : req.body.country : req.body.country;

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { country, offset, limit }

            const zodObj = zod.object({
                country: zod.string(),
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE country = ? AND deleted_at IS NULL ORDER BY user_id LIMIT $2 OFFSET $3`, [country, valueLimit, valueOffset]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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

    getUsersByDeletedAt = async (req, res) => {

        try {

            const offset = req.body.offset;

            const limit = req.body.limit;

            const reqBodyData = { offset, limit }

            const zodObj = zod.object({
                offset: zod.number().int().optional(),
                limit: zod.number().int().optional()
            });

            zodObj.parse(reqBodyData);

            const valueOffset = typeof offset === 'undefined' ? 0 : offset;

            const valueLimit = typeof limit === 'undefined' ? Number.MAX_SAFE_INTEGER : limit;

            const [rows] = await this.sql.query(`SELECT user_id, first_name, middle_name, last_name, nick_name, u_id, email, roles, status, ban_status, ban_by, image, about, country, contact, first_login_ip, last_login_ip, created_at, updated_at, deleted_at FROM users WHERE deleted_at IS NOT NULL ORDER BY user_id LIMIT ?, ?`, [valueOffset, valueLimit]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            
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

    /////////////////////////////////////////////////////////////////////////////////////

    /* update user/users */

    /////////////////////////////////////////////////////////////////////////////////////

    updateUserFirstName = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const first_name = req.body.first_name ? (typeof req.body.first_name == "string") ? req.body.first_name.trim() : req.body.first_name : req.body.first_name;

            const reqBodyData = { user_id, email, u_id, first_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                first_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET first_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [first_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserFirstNameByHr = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const first_name = req.body.first_name ? (typeof req.body.first_name == "string") ? req.body.first_name.trim() : req.body.first_name : req.body.first_name;

            const reqBodyData = { user_id, email, u_id, first_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                first_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const accessRoles = [
                "SUPERADMIN",
                "ADMIN",
                "MANAGER",
            ];

            const roles = rows[0]?.roles ? JSON.parse(rows[0]?.roles) : [];

            const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

            if (accessArray) return res.json({ error: true, data: "Unauthorized role!" });

            const resultUpdated = await this.sql.query(`UPDATE users SET first_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserMiddleName = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const middle_name = req.body.middle_name ? (typeof req.body.middle_name == "string") ? req.body.middle_name.trim() : req.body.middle_name : req.body.middle_name;

            const reqBodyData = { user_id, email, u_id, middle_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                middle_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET middle_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [middle_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserMiddleNameByHr = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const middle_name = req.body.middle_name ? (typeof req.body.middle_name == "string") ? req.body.middle_name.trim() : req.body.middle_name : req.body.middle_name;

            const reqBodyData = { user_id, email, u_id, middle_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                middle_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const accessRoles = [
                "SUPERADMIN",
                "ADMIN",
                "MANAGER",
            ];

            const roles = rows[0]?.roles ? JSON.parse(rows[0]?.roles) : [];

            const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

            if (accessArray) return res.json({ error: true, data: "Unauthorized role!" });

            const resultUpdated = await this.sql.query(`UPDATE users SET middle_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [middle_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserLastName = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const last_name = req.body.last_name ? (typeof req.body.last_name == "string") ? req.body.last_name.trim() : req.body.last_name : req.body.last_name;

            const reqBodyData = { user_id, email, u_id, last_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                last_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET last_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [last_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserLastNameByHr = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const last_name = req.body.last_name ? (typeof req.body.last_name == "string") ? req.body.last_name.trim() : req.body.last_name : req.body.last_name;

            const reqBodyData = { user_id, email, u_id, last_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                last_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const accessRoles = [
                "SUPERADMIN",
                "ADMIN",
                "MANAGER",
            ];

            const roles = rows[0]?.roles ? JSON.parse(rows[0]?.roles) : [];

            const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

            if (accessArray) return res.json({ error: true, data: "Unauthorized role!" });

            const resultUpdated = await this.sql.query(`UPDATE users SET last_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [last_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserNickName = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const nick_name = req.body.nick_name ? (typeof req.body.nick_name == "string") ? req.body.nick_name.trim() : req.body.nick_name : req.body.nick_name;

            const reqBodyData = { user_id, email, u_id, nick_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                nick_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET nick_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [nick_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserNickNameByUser = async (req, res) => {

        try {

            const id = c?.id;

            const email = c?.email ? (typeof c?.email == "string") ? c?.email.trim().toLowerCase() : c?.email : c?.email;

            const u_id = c?.u_id ? (typeof c?.u_id == "string") ? c?.u_id.trim() : c?.u_id : c?.u_id;

            const nick_name = req.body.nick_name ? (typeof req.body.nick_name == "string") ? req.body.nick_name.trim() : req.body.nick_name : req.body.nick_name;

            const reqBodyData = { user_id, email, u_id, nick_name };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                nick_name: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET nick_name = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [nick_name, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserEmail = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const email_new = req.body.email_new ? (typeof req.body.email_new == "string") ? req.body.email_new.trim().toLowerCase() : req.body.email_new : req.body.email_new;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, email_new,  u_id };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email(),
                email_new: zod.string().email(),
                u_id: zod.string().optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const emailNewData = typeof email === 'undefined' ? '' : email_new;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdate = await this.sql.query(`UPDATE users SET email = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [emailNewData, idData, emailData, uIdData]);

            if (resultUpdate.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserPassword = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const password = req.body.password ? (typeof req.body.password == "string") ? req.body.password.trim() : req.body.password : req.body.password;

            const reqBodyData = { user_id, email, u_id, password };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                password: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const hashedPassword = bcrypt.hashSync(password, 10);

            const resultUpdated = await this.sql.query(`UPDATE users SET password = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [hashedPassword, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserRoles = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const roles = req.body.roles ? (typeof req.body.roles == "string") ? req.body.roles.trim() : req.body.roles : req.body.roles;

            const reqBodyData = { user_id, email, u_id, roles };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                roles: zod.array(zod.string()),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const rolesData = roles.map((role) => role.trim().toUpperCase())

            const resultUpdated = await this.sql.query(`UPDATE users SET roles = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [JSON.stringify(rolesData), idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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


    updateUserStatus0 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account marked deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET status = 0 WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserStatus1 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account marked deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET status = 1 WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserBanStatus0 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account marked deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET ban_status = 0, ban_by = 0 WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserBanStatus1 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account marked deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET ban_status = 1, ban_by = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [c?.user_id, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserImage = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const image = req.body.image ? (typeof req.body.image == "string") ? req.body.image.trim() : req.body.image : req.body.image;

            const reqBodyData = { user_id, email, u_id, image };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                image: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET image = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [image, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserImageByUser = async (req, res) => {

        try {

            const id = c?.id;

            const email = c?.email ? (typeof c?.email == "string") ? c?.email.trim().toLowerCase() : c?.email : c?.email;

            const u_id = c?.u_id ? (typeof c?.u_id == "string") ? c?.u_id.trim() : c?.u_id : c?.u_id;

            const image = req.body.image ? (typeof req.body.image == "string") ? req.body.image.trim() : req.body.image : req.body.image;

            const reqBodyData = { user_id, email, u_id, image };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                image: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET image = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [image, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserAbout = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const about = req.body.about ? (typeof req.body.about == "string") ? req.body.about.trim() : req.body.about : req.body.about;

            const reqBodyData = { user_id, email, u_id, about };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                about: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET about = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [about, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserAboutByUser = async (req, res) => {

        try {

            const id = c?.id;

            const email = c?.email ? (typeof c?.email == "string") ? c?.email.trim().toLowerCase() : c?.email : c?.email;

            const u_id = c?.u_id ? (typeof c?.u_id == "string") ? c?.u_id.trim() : c?.u_id : c?.u_id;

            const about = req.body.about ? (typeof req.body.about == "string") ? req.body.about.trim() : req.body.about : req.body.about;

            const reqBodyData = { user_id, email, u_id, about };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                about: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET about = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [about, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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


    updateUserCountry = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const country = req.body.country ? (typeof req.body.country == "string") ? req.body.country.trim() : req.body.country : req.body.country;

            const reqBodyData = { user_id, email, u_id, country };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                country: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET country = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [country, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserCountryByHr = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const country = req.body.country ? (typeof req.body.country == "string") ? req.body.country.trim() : req.body.country : req.body.country;

            const reqBodyData = { user_id, email, u_id, country };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                country: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const accessRoles = [
                "SUPERADMIN",
                "ADMIN",
                "MANAGER",
            ];

            const roles = rows[0]?.roles ? JSON.parse(rows[0]?.roles) : [];

            const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

            if (accessArray) return res.json({ error: true, data: "Unauthorized role!" });

            const resultUpdated = await this.sql.query(`UPDATE users SET country = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [country, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserContact = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const contact = req.body.contact ? (typeof req.body.contact == "string") ? req.body.contact.trim() : req.body.contact : req.body.contact;

            const reqBodyData = { user_id, email, u_id, contact };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                contact: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET contact = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [contact, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });


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

    updateUserContactByHr = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const contact = req.body.contact ? (typeof req.body.contact == "string") ? req.body.contact.trim() : req.body.contact : req.body.contact;

            const reqBodyData = { user_id, email, u_id, contact };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                contact: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const accessRoles = [
                "SUPERADMIN",
                "ADMIN",
                "MANAGER",
            ];

            const roles = rows[0]?.roles ? JSON.parse(rows[0]?.roles) : [];

            const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

            if (accessArray) return res.json({ error: true, data: "Unauthorized role!" });

            const resultUpdated = await this.sql.query(`UPDATE users SET contact = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [contact, idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserTokens = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const tokens = req.body.tokens ? (typeof req.body.tokens == "string") ? req.body.tokens.trim() : req.body.tokens : req.body.tokens;

            const reqBodyData = { user_id, email, u_id, tokens };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                tokens: zod.array(zod.string()),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET tokens = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [JSON.stringify(tokens), idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserAssignmentUser0 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id};

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET assignment_user = 0 WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserAssignmentUser1 = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET assignment_user = 1 WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserWebsiteData = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const user_website_data = req.body.user_website_data;

            const reqBodyData = { user_id, email, u_id, user_website_data };

            const zodObj = zod.object({
                user_id: zod.number().int().optional(),
                email: zod.string().email().optional(),
                u_id: zod.string().optional(),
                user_website_data: zod.array(zod.any()),
            });

            zodObj.parse(reqBodyData);

            if (!(user_id || email || u_id)) return res.json({ error: true, data: "Please provide (user_id or email or u_id!" });

            const idData = typeof user_id === 'undefined' ? 0 : user_id;

            const emailData = typeof email === 'undefined' ? '' : email;

            const uIdData = typeof u_id === 'undefined' ? '' : u_id;

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

            if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

            if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

            if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

            const resultUpdated = await this.sql.query(`UPDATE users SET user_website_data = ? WHERE user_id = ? OR email = ? OR u_id = ?`, [JSON.stringify(user_website_data), idData, emailData, uIdData]);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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



    updateUserDeletedAt = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at !== null) {
                
                return res.json({ error: true, data: "User account already marked deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET deleted_at = LOCALTIMESTAMP(0) WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUserDeletedAtNull = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at === null) {
                
                return res.json({ error: true, data: "User account already marked not deleted!" });
            }

            const resultUpdated = await this.sql.query(`UPDATE users SET deleted_at = NULL WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultUpdated.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `User data updated successfully!` });

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

    updateUsersRoles = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const roles = req.body.roles;

            const reqBodyData = { ids, emails, u_ids, roles };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
                roles: zod.array(zod.string()),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const rolesData = roles.map((role) => role.trim().toUpperCase());

            const result = await this.sql.query(`UPDATE users SET roles = ? WHERE id IN ($)2 OR email IN ($3) OR u_id IN ($4) AND deleted_at IS NULL`, [JSON.stringify(rolesData), idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    updateUsersStatus0 = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET status = 0 WHERE id IN (?) OR email IN (?) OR u_id IN (?) AND deleted_at IS NULL`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    updateUsersStatus1 = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET status = 1 WHERE id IN (?) OR email IN (?) OR u_id IN (?) AND deleted_at IS NULL`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Usersdata updated successfully!` });

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

    updateUsersBanStatus0 = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional()
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET ban_status = 0 WHERE id IN (?) OR email IN (?) OR u_id IN (?) AND deleted_at IS NULL`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    updateUsersBanStatus1 = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET ban_status = 1 WHERE id IN (?) OR email IN (?) OR u_id IN (?) AND deleted_at IS NULL`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    updateUsersDeletedAt = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET deleted_at = LOCALTIMESTAMP(0) WHERE id IN (?) OR email IN (?) OR u_id IN (?)`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    updateUsersDeletedAtNull = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const result = await this.sql.query(`UPDATE users SET deleted_at = NULL WHERE id IN (?) OR email IN (?) OR u_id IN (?)`, [idsData, emailsData, uidsData]);

            if (result.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to update data!" });
            }
            return res.json({ error: false, data: `Users data updated successfully!` });

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

    /////////////////////////////////////////////////////////////////////////////////////

    /* Delete user/users */

    /////////////////////////////////////////////////////////////////////////////////////

    deleteUser = async (req, res) => {

        try {

            const user_id = req.body.user_id;

            const email = req.body.email ? (typeof req.body.email == "string") ? req.body.email.trim().toLowerCase() : req.body.email : req.body.email;

            const u_id = req.body.u_id ? (typeof req.body.u_id == "string") ? req.body.u_id.trim() : req.body.u_id : req.body.u_id;

            const reqBodyData = { user_id, email, u_id };

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

            const [rows] = await this.sql.query(`SELECT roles, status, ban_status, ban_by, deleted_at FROM users WHERE user_id = ? OR email = ? OR u_id = ?`, [idData, emailData, uIdData]);

            if (rows.length === 0) return res.json({ error: true, data: "User account not found!" });
            

            if (rows[0].deleted_at === null) {
                
                return res.json({ error: true, data: "User account must marked deleted!" });
            }

            const resultDeleted = await this.sql.query(`DELETE FROM users WHERE id = ${idData} OR email = ${emailData} OR u_id = ${uIdData}`, []);

            if (resultDeleted.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to delete data!" });
            }
            return res.json({ error: false, data: `Users data deleted successfully!` });

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

    deleteUsers = async (req, res) => {

        try {

            const ids = req.body.ids;

            const emails = req.body.emails;

            const u_ids = req.body.u_ids;

            const reqBodyData = { ids, emails, u_ids };

            const zodObj = zod.object({
                ids: zod.array(zod.number().int()).optional(),
                emails: zod.array(zod.string().email()).optional(),
                u_ids: zod.array(zod.string()).optional(),
            });

            zodObj.parse(reqBodyData);

            if (!(ids || emails || u_ids)) return res.json({ error: true, data: "Please provide ids or emails or u_ids!" });

            const idsData = typeof ids === 'undefined' || typeof ids !== 'object' ? [] : ids;

            const emailsData = typeof emails === 'undefined' || typeof emails !== 'object' ? [] : emails.map((email) => email.trim().toLowerCase());

            const uidsData = typeof u_ids === 'undefined' || typeof u_ids !== 'object' ? [] : u_ids;

            const resultDeleted = await this.sql.query(`DELETE FROM users WHERE id IN (?) OR email IN (?) OR u_id IN (?) AND deleted_at IS NOT NULL`, [idsData, emailsData, uidsData]);

            if (resultDeleted.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to delete data!" });
            }
            return res.json({ error: false, data: `User data deleted successfully!` });

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


    deleteAllUsers = async (req, res) => {

        try {

            const super_admin_secret = req.body.super_admin_secret ? (typeof req.body.super_admin_secret == "string") ? req.body.super_admin_secret.trim() : req.body.super_admin_secret : req.body.super_admin_secret;

            const reqBodyData = { super_admin_secret };

            const zodObj = zod.object({

                emails: zod.array(zod.string().email()).optional(),
                super_admin_secret: zod.string(),
            });

            zodObj.parse(reqBodyData);

            if (!super_admin_secret) return res.json({ error: true, data: "Please provide super_admin_secret!" });

            const resultDeleted = await this.sql.query(`DELETE FROM users WHERE deleted_at IS NOT NULL`, []);

            if (resultDeleted.rowCount === 0) {
                
                return res.json({ error: true, data: "Unable to delete data!" });
            }
            return res.json({ error: false, data: `User data deleted successfully!` });

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

    createTable = async (req, res) => {

        try {

            const resultCreateTbale = await this.sql.query(`DROP TABLE IF EXISTS users`);

            await this.sql.query(`CREATE TABLE users (
                user_id bigint UNSIGNED NOT NULL AUTO_INCREMENT,
                first_name varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
                middle_name varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
                last_name varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
                nick_name varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
                u_id varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
                email varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
                password longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
                roles longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                status tinyint NOT NULL DEFAULT '1',
                ban_status tinyint NOT NULL DEFAULT '0',
                ban_by bigint DEFAULT '0',
                image varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
                about mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                country varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'India',
                contact varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT '1234567890',
                first_login_ip varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT '0.0.0.0',
                last_login_ip varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT '0.0.0.0',
                tokens longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                login_devices longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                allowed_devices longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                max_allowed_devices int UNSIGNED NOT NULL DEFAULT '2',
                login_instances int UNSIGNED DEFAULT '0',
                allowed_login_instances int UNSIGNED NOT NULL DEFAULT '2',
                assignment_user tinyint NOT NULL DEFAULT '0',
                user_website_data longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                others longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                deleted_at timestamp NULL DEFAULT NULL,
                PRIMARY KEY (user_id),
                UNIQUE KEY email (email),
                UNIQUE KEY u_id (u_id)
              ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`, []);
            return res.json({ error: false, data: `Table users created successfully!`, resultCreateTbale });

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

    dropTable = async (req, res) => {

        try {

            const resultDropTable = await this.sql.query(`DROP TABLE IF EXISTS users`, []);

            return res.json({ error: false, data: `Table users deleted successfully!`, resultDropTable });

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

    test = async (req, res) => {

        try {

            const [rows] = await this.sql.query(`SELECT * FROM pg_stat_activity WHERE datname = 'defaultdb'`, []);

            console.log(result)

            return res.json({ error: false, data: result });

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

    app = async (req, res) => {

        try {

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API_APP);

            const rows = [
                {
                    user_id: 0,

                    u_id: `0`,

                    email: `app@lcapis.app`,

                    roles: JSON.stringify(["APP"]),
                }
            ]

            const jwtToken = await new jose.SignJWT({ data: rows })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 * 12)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

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

    cron = async (req, res) => {

        try {

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API_CRON);

            const rows = [
                {
                    user_id: 0,

                    u_id: `0`,

                    email: `cron@lcapis.app`,

                    roles: JSON.stringify(["CRON"]),
                }
            ]

            const jwt = await new jose.SignJWT({ data: rows })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 * 12)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwt) });

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

    jwt = async (req, res) => {

        try {

            const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY_USERS_API);

            const rows = [
                {
                    user_id: 0,

                    u_id: `0`,

                    email: `app@lcapis.app`,

                    roles: JSON.stringify(["APP"]),
                }
            ]

            const jwtToken = await new jose.SignJWT({ data: rows })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setIssuer(process.env.ISSUER)
                .setAudience(process.env.AUDIENCE)
                .setExpirationTime(Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 * 12)
                .sign(secret)

            return res.json({ error: false, data: cryptApi.encrypt(jwtToken) });

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

export default UsersController