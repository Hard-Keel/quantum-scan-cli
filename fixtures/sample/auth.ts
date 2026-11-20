// Sample code with planted quantum-vulnerable crypto.
import { generateKeyPairSync, createECDH, createHash } from "node:crypto";
import jwt from "jsonwebtoken";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ecdh = createECDH("prime256v1");
export const token = (claims: object) => jwt.sign(claims, privateKey, { algorithm: "RS256" });
export const etag = (body: string) => createHash("sha1").update(body).digest("hex");
