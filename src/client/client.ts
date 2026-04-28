import WebSocket, {RawData} from 'ws';
import { MSG, encode, decode, InnerMessage } from '../shared/protocol.js';
import {
    generateKeyPair,
    deriveSharedKey,
    encryptJson,
    decryptJson
} from '../shared/crypto.js';

//Simulates the ThinClient
type AuthResponse =
    | {
    ok: true;
    token: string;
    username: string;
    groups: string[];
}
    | {
    ok: false;
    error?: string;
};

const APP_WS_URL = process.env.APP_WS_URL ?? 'ws://localhost:5000';

const clientKeys = generateKeyPair(); //Generates Keys for client

let clientId: string | null = null;
let sharedKey: Buffer | null = null;
let userToken: string | null = null;

const ws = new WebSocket(APP_WS_URL); //establish websocket connection to application

function sendToAgent(inner: InnerMessage) { //Uses the web Socket connection to send information to the agent
    ws.send(
        encode({
            type: MSG.RELAY,
            to: 'agent',
            inner
        })
    );
}

function requireSharedKey(): Buffer {
    if (!sharedKey) {
        throw new Error('E2E shared key not established');
    }

    return sharedKey;
}
//Client send request to the application so it can register the client
ws.on('open', () => {
    ws.send(
        encode({
            type: MSG.REGISTER,
            role: 'client'
        })
    );

    console.log('[client] connected to application');
});

ws.on('message', (raw) => {
    let msg: any;
    msg = decode(raw);

    if (msg.type === 'registered') {
        //Client successfully registered
        clientId = msg.clientId;

        console.log(`[client] registered as ${clientId}`);
        //Send to agent the handshake message
        sendToAgent({
            type: MSG.E2E_HELLO,
            clientPublicKeyPem: clientKeys.publicKey.export({
                type: 'spki',
                format: 'pem'
            })
        });

        return;
    }
    if (msg.type === MSG.PROFILE_RESPONSE) {
        console.log('[client] profile received:', msg.profile);
        console.log('[client] user session ready');
        return;
    }

    if (msg.type === MSG.ACCESS_DENIED) {
        console.log('[client] access denied');
        console.log('[client] reason:', msg.reason);
        return;
    }

    if (msg.type !== MSG.RELAY) { //if message received is no relay -> return
        return;
    }
    //Gets the inner message that was sent from the agent
    const inner: InnerMessage = msg.inner;

    switch (inner.type) {
        case MSG.E2E_HELLO_REPLY: { //Handshake reply and establish e2e encrypted channel
            sharedKey = deriveSharedKey(
                clientKeys.privateKey,
                inner.agentPublicKeyPem
            );

            console.log('[client] E2E encrypted channel established');

            const encryptedCredentials = encryptJson( // credentials that will be authenticated are sent encrypted
                {
                    username: 'testuser',
                    password: 'Passw0rd!'
                },
                sharedKey
            );

            sendToAgent({ //Sends the request to the Agent for authentication with the encrypted credentials
                type: MSG.E2E_AUTH_REQUEST,
                payload: encryptedCredentials
            });

            console.log('[client] encrypted credentials sent to agent');

            break;
        }

        case MSG.E2E_AUTH_RESPONSE: {
            //gets the key
            const key = requireSharedKey();
            //decrypts the JSON response object
            const authResult = decryptJson(inner.payload, key) as AuthResponse;

            console.log('[client] auth response:', authResult);

            if (!authResult.ok) {
                console.log('[client] authentication failed');
                return;
            }

            userToken = authResult.token; //Saves the token that the agent generated

            console.log(`[client] authenticated as ${authResult.username}`);
            console.log('[client] token received');

            ws.send(
                encode({
                    type: MSG.CLIENT_REPORT,
                    token: userToken
                })
            );

            console.log('[client] token sent for validation');

            break;
        }

        default:
            console.warn('[client] unknown message:', inner);
    }
});

ws.on('close', () => {
    console.log('[client] disconnected from application');
});

ws.on('error', (error) => {
    console.error('[client] websocket error:', error);
});