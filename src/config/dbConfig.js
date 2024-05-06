import * as dotenv from "dotenv";

dotenv.config();

import mysql from "mysql2";

const dbConfig = {

  host: process.env.DB_HOST,
  port: process.env.DB_PORT ? +process.env.DB_PORT : 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    sslmode: 'verify-full',
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 111,
  queueLimit: 0,
  enableKeepAlive: true,
  dateStrings: true,
  typeCast(field, next) {
    if (field.type == 'DATETIME') {
      const utcTime = Math.floor((new Date(field.string() + " UTC")).getTime() / 1000);
      const fixedDate = new Date(0);
      fixedDate.setUTCSeconds(utcTime);
      return fixedDate;
    }
    return next();

  }
};

// const dbConfig = {

//   host: process.env.LOCAL_DB_HOST,
//   port: process.env.LOCAL_DB_PORT ? +process.env.LOCAL_DB_PORT : 3306,
//   user: process.env.LOCAL_DB_USER,
//   password: process.env.LOCAL_DB_PASSWORD,
//   database: process.env.LOCAL_DB_NAME,
//   waitForConnections: true,
//   connectionLimit: 111,
//   queueLimit: 0,
//   enableKeepAlive: true,
//   dateStrings: true,
//   typeCast(field, next) {
//     if (field.type == 'DATETIME') {
//       const utcTime = Math.floor((new Date(field.string() + " UTC")).getTime() / 1000);
//       const fixedDate = new Date(0);
//       fixedDate.setUTCSeconds(utcTime);
//       return fixedDate;
//     }
//     return next();

//   }
// };

const pool = mysql.createPool(dbConfig);

export default pool