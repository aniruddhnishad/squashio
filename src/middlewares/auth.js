
import * as dotenv from "dotenv";

dotenv.config();

import * as jose from "jose";

import pool from "../config/dbConfig.js";

import cryptApi from "../helpers/cryptApi.js";

const JWT_SECRET_KEY_USERS_API = process.env.JWT_SECRET_KEY_USERS_API;

const auth = async (req, res, next) => {

  const authHeader = await req.header('authorization');

  if (!authHeader) return res.json({ error: true, data: "Authorization header not available!" });

  if (!authHeader.startsWith('Bearer')) return res.json({ error: true, data: "Not A Beader authorization header!" });

  const encryptedToken = authHeader.split(" ")[1];

  try {

    const token = cryptApi.decrypt(encryptedToken);
    
    const secret = new TextEncoder().encode(JWT_SECRET_KEY_USERS_API);

    const jwtVerifyData = await jose.jwtVerify(token, secret, {
      issuer: process.env.ISSUER,
      audience: process.env.AUDIENCE,
    });
    const payload = jwtVerifyData.payload;

    const user_id = payload?.data[0]?.user_id ? +payload?.data[0]?.user_id : payload?.data[0]?.user_id;

    const email = payload?.data[0]?.email;

    const u_id = payload?.data[0]?.u_id ? payload?.data[0]?.u_id : 0;

    const sql = pool.promise();

    const [rows] = await sql.query("SELECT * FROM users WHERE user_id = ? OR email = ? OR u_id = ?", [user_id, email, u_id]);

    if (rows?.length === 0) return res.json({ error: true, data: "USER_NOT_FOUND" });

    if (+rows[0]?.status === 0) return res.json({ error: true, data: "USER_STATUS_INACTIVE" });

    if (+rows[0]?.ban_status === 1 || +rows[0]?.ban_by !== 0) return res.json({ error: true, data: "USER_STATUS_BAN" });

    if (rows[0]?.deleted_at !== null) return res.json({ error: true, data: "USER_STATUS_DELETED" });

    const tokens = rows[0].tokens ? JSON.parse(rows[0].tokens) : [];

    if (!tokens.includes(encryptedToken)) return res.json({ error: true, data: "UNAUTHORIZED_INVALID_TOKEN" });
    
    req.user_id = user_id;

    req.u_id = u_id;

    req.email = email;

    req.roles = payload?.data[0]?.roles ? JSON.parse(payload?.data[0]?.roles) : [];

    req.token = encryptedToken;

    await next();

  } catch (error) {

    console.log(error)

    return res.json({ error: true, data: error.message });

  }

}

export default auth