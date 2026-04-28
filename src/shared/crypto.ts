import crypto from 'node:crypto';
import { EncryptedPayload } from './protocol.js';
//Handles the e2e encrypted channel between client and agent
export function generateKeyPair() {
    //Generates public and private Key
    return crypto.generateKeyPairSync('x25519'); //x25519 for Diffie-Hellman
}

//Generates the shared secret ciphertext.
//Both Client and Agent use this function
//Client uses: its private and the agents public key
//Agent uses its private and the clients private key
export function deriveSharedKey(
    privateKey: crypto.KeyObject,
    otherPublicKeyPem: string
): Buffer {
    const otherPublicKey = crypto.createPublicKey(otherPublicKeyPem);

    const secret = crypto.diffieHellman({
        privateKey,
        publicKey: otherPublicKey
    });

    return crypto.createHash('sha256').update(secret).digest(); //Sends the message in hashed 32 Bytes Cipher for later AES-256-GCM
}

//Encrypts a JSON Object
export function encryptJson(obj: any, key: Buffer): EncryptedPayload {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(obj)),
        cipher.final()
    ]);

    return { //Returns AES-256-GCM encryption payload
        iv: iv.toString('base64'),
        ciphertext: encrypted.toString('base64'),
        tag: cipher.getAuthTag().toString('base64')
    };
}

//Decrypts encrypted payload and converts it to a JSON object
export function decryptJson(payload: EncryptedPayload, key: Buffer): any {
    //Only endpoints that negotiated the Key can decrypt the ciphertext
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(payload.iv, 'base64')
    );

    decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payload.ciphertext, 'base64')),
        decipher.final()
    ]);

    return JSON.parse(decrypted.toString());
}