import * as dotenv from "dotenv";

dotenv.config();

import crypto from "crypto";

const hashKeyApi = crypto.createHash('sha256');
hashKeyApi.update(process.env.ENCRYPTION_KEY_API || '');
const keyApi = hashKeyApi.digest('hex').substring(0, 32);

const hashIvApi = crypto.createHash('sha256');
hashIvApi.update(process.env.ENCRYPTION_KEY_API || "");
const ivApi = hashIvApi.digest('hex').substring(0, 16);

const cryptApi = {
    encrypt: (value = '') => {
        const cipher = crypto.createCipheriv('AES-256-CBC', keyApi, ivApi);
        const encrypted = cipher.update(value, 'utf-8', 'base64') + cipher.final('base64');
        return Buffer.from(encrypted, 'utf-8').toString('base64');
    },

    decrypt: (value = '') => {
        const encrypted = Buffer.from(value, 'base64').toString('utf-8');
        const decipher = crypto.createDecipheriv('AES-256-CBC', keyApi, ivApi);
        return decipher.update(encrypted, 'base64', 'utf-8') + decipher.final('utf-8');
    }
}

export default cryptApi