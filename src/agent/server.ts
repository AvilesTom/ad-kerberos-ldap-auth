import WebSocket from 'ws';
import jwt from 'jsonwebtoken';
import { MSG, encode, decode, InnerMessage } from '../shared/protocol.js';
import {
    generateKeyPair,
    deriveSharedKey,
    encryptJson,
    decryptJson
} from '../shared/crypto.js';
import crypto from 'node:crypto';
import  { Client } from 'ldapts';
import kerberos from'kerberos';

//This agent server solver 4 principal things:
// 1- Connects to application
// 2- Establish e2e encrypted channel
// 3- Validates credentials against AD
// Emits and validates Tokens

// ------------------- Types Definition ----------------------
type Session = {
    sharedKey: Buffer;
};

type AdAuthSuccess = {
    ok: true;
    username: string;
    groups: string[];
};

type AdAuthFailure = {
    ok: false;
};

type AdAuthResult = AdAuthSuccess | AdAuthFailure;

type Credentials = {
    username: string;
    password: string;
};

type LdapUser = {
    username: string;
    dn: string;
    groups: string[];
}

//LDAP CONNECTION CONFIG
const LDAP_URL = process.env.LDAP_URL ?? 'ldap://localhost:389';
const LDAP_BIND_DN = process.env.LDAP_BIND_DN ?? '';
const LDAP_BIND_PASSWORD = process.env.LDAP_BIND_PASSWORD;
const LDAP_USER_SEARCH_BASE = 'dc=example,dc=local';
const LDAP_USER_FILER = '(sAMAccountName={{username}})';

//KERBEROS CONNECTION CONFIG
const KRB_REALM = process.env.KRB_REALM ?? 'EXAMPLE.LOCAL';
const KRB_SERVICE = process.env.KRB_SERVICE ?? 'ldap/dc1.example.local';


const APP_WS_URL = process.env.APP_WS_URL ?? 'ws://localhost:5000'; //Endpoint to application
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

const sessions = new Map<string, Session>(); // saves the e2e client and shared key. Every client has a ciphered channel wih the agent

const agentKeys = generateKeyPair(); //Generates keypair for handshake

/**
 * This function authenticates first the credentials and then searches for the requested user in the AD
 * @param username
 * @param password
 */
async function authenticateAgainstAd(
    username: string,
    password: string
): Promise<AdAuthResult> {
    const kerberos = authenticateWithKerberos(username, password);
    if(!kerberos){
        return { ok: false };
    }
    //searches the user
    const ldapUser = await findUserWithLdap(username);

    if ( !ldapUser ){
        return { ok: false }
    }
    return {
        ok: true,
        username: ldapUser.username,
        groups: ldapUser.groups
    }
}

/**
 * In this function we use kerberos for Authentication
 * @param username
 * @param password
 */
async function authenticateWithKerberos(username: string, password: string): Promise<Boolean>{
    //define the constant for the search: if already has @ keep it, if not add it
    const principal = username.includes('@') ? username : `${username}@${KRB_REALM}`;
    try {
        await kerberos.checkPassword(
          principal,
          password,
          KRB_SERVICE,
          KRB_REALM
        );
        return true;
    } catch (error){
        const message = error instanceof Error ? error.message : String(error);
        console.warn(`[agent][kerberos] auth failed for ${principal}: ${message}`);
        return false;
    }
}
async function findUserWithLdap(username: string): Promise<LdapUser | null>{
    //Creates a new LDAP Client
    const client = new Client ({
        url: LDAP_URL,
        tlsOptions: {
            rejectUnauthorized: false
        }
    });
    try {
        await client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD);
        const filter = LDAP_USER_FILER.replace('{{username}}', filterValue(username));

        //makes the search
        const { searchEntries } = await client.search(LDAP_USER_SEARCH_BASE, {
            scope: 'sub',
            filter, //WHERE sAMAccountName = username
            attributes: [
                'dn',
                'cn',
                'sAMAccountName',
                'memberOf'
            ]
        });

        if (searchEntries.length != 1){ //None or more than one user found
            console.warn(`[agent][ldap] user not found or not unique: ${username}`);
            return null;
        }
        const entry = searchEntries[0];

        return {
            dn: String(entry.dn),
            username: String(entry.sAMAccountName ?? username),
            groups: normalizeLdapStringAray (entry.memberOf)
        };
    } catch (error){
        const message = error instanceof Error ? error.message : String(error);
        console.warn(`[agent][ldap] lookup failed for ${username}: ${message}`);
        return null;
    } finally {
        await client.unbind().catch(() => {});
    }
}

//Format the Array of groups if any
function normalizeLdapStringAray(value: unknown): string[]{
    if(!value){
        return  [];
    }
    if(Array.isArray(value)){
        return value.map(String);
    }
    return [String(value)];
}

/**
 * Sanitize the search entries for LDAP
 * @param value
 */
function filterValue(value: string): string {
    return value
        .replace(/\\/g, '\\5c')
        .replace(/\*/g, '\\2a')
        .replace(/\(/g, '\\28')
        .replace(/\)/g, '\\29')
        .replace(/\0/g, '\\00');
}

//Sets the flag RELAY so it can pass to the client
function sendToClient(ws: WebSocket, clientId: string, inner: InnerMessage) {
    ws.send(
        encode({
            type: MSG.RELAY,
            to: clientId,
            inner
        })
    );
}

const ws = new WebSocket(APP_WS_URL); //Establish a socket to application

ws.on('open', () => {
    ws.send(
        encode({ //for application: register the agent and its socket
            type: MSG.REGISTER,
            role: 'agent'
        })
    );

    console.log('[agent] connected to application');
});

ws.on('message', async (raw) => {
    const msg = decode<any>(raw); //decode raw data

    if (msg.type !== MSG.RELAY) {
        return; //If type of the message is not relay returns
    }

    const clientId: string = msg.from;  //gets client ID
    const inner: InnerMessage = msg.inner; //Gets the message

    switch (inner.type) {
        case MSG.E2E_HELLO: { //handshake
            const sharedKey = deriveSharedKey(
                agentKeys.privateKey,
                inner.clientPublicKeyPem
            ); //creates secret shared cipher

            sessions.set(clientId, { sharedKey }); //stores the secret share cipher into the session

            console.log(`[agent] E2E session established with ${clientId}`);

            sendToClient(ws, clientId, { //responds with its own public key
                type: MSG.E2E_HELLO_REPLY,
                agentPublicKeyPem: agentKeys.publicKey.export({
                    type: 'spki',
                    format: 'pem'
                })
            });
            //From this point agent and client can encrypt messages between each other
            break;
        }

        case MSG.E2E_AUTH_REQUEST: { //Gets auth request from the client
            const session = sessions.get(clientId); //Sts the session if already made the handshake

            if (!session) {
                console.warn(`[agent] no E2E session for ${clientId}`);
                return;
            }

            try {
                //Uses crypto to decrypt object received
                const credentials = decryptJson(
                    inner.payload,
                    session.sharedKey
                ) as Credentials; //Defines it as type Credentials

                console.log(`[agent] received encrypted auth request for ${credentials.username}`);

                //Tries to authenticate with the credentials against AD
                const adResult = await authenticateAgainstAd(
                    credentials.username,
                    credentials.password
                );

                if (!adResult.ok) { //No valid credentials
                    //Encrypts the payload and the shared key
                    sendToClient(ws, clientId, {
                        type: MSG.E2E_AUTH_RESPONSE,
                        payload: encryptJson(
                            {
                                ok: false,
                                error: 'Invalid credentials'
                            },
                            session.sharedKey
                        )
                    });

                    return;
                }

                //Generates Token with the given credentials
                const token = jwt.sign(
                    {
                        sub: adResult.username,
                        groups: adResult.groups,
                        iss: 'agent',
                        scope: 'thin-client'
                    },
                    JWT_SECRET, //SECRET
                    {
                        expiresIn: '15m'
                    }
                );

                sendToClient(ws, clientId, {
                    //IF CORRECTLY AUTHENTICATED IT SENDS THE RESPONSE AND THE SHARE KEY
                    type: MSG.E2E_AUTH_RESPONSE,
                    payload: encryptJson(
                        {
                            ok: true,
                            token,
                            username: adResult.username,
                            groups: adResult.groups
                        },
                        session.sharedKey
                    )
                });

                console.log(`[agent] auth successful for ${adResult.username}`);
            } catch (error) {
                const message = error instanceof Error ? error.message : 'Unknown error';

                sendToClient(ws, clientId, {
                    type: MSG.E2E_AUTH_RESPONSE,
                    payload: encryptJson(
                        {
                            ok: false,
                            error: message
                        },
                        session.sharedKey
                    )
                });
            }

            break;
        }

        case MSG.VALIDATE_TOKEN: { //Agent tries to validate a token received from the application
            try {
                const claims = jwt.verify(inner.token, JWT_SECRET); //verifies the given token

                sendToClient(ws, clientId, {
                    type: MSG.VALIDATE_TOKEN_RESULT,
                    ok: true,
                    claims
                });

                console.log(`[agent] token valid for ${clientId}`);
            } catch {
                sendToClient(ws, clientId, {
                    type: MSG.VALIDATE_TOKEN_RESULT,
                    ok: false
                });

                console.log(`[agent] token invalid for ${clientId}`);
            }

            break;
        }

        default:
            console.warn('[agent] unknown message:', inner);
    }
});

ws.on('close', () => {
    console.log('[agent] disconnected from application');
});

ws.on('error', (error) => {
    console.error('[agent] websocket error:', error);
});