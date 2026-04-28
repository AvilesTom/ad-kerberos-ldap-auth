//Type of message
import WebSocket from "ws";

export enum MSG {
    REGISTER = 'register',
    RELAY = 'relay',

    E2E_HELLO = 'e2e_hello',
    E2E_HELLO_REPLY = 'e2e_hello_reply',

    E2E_AUTH_REQUEST = 'e2e_auth_request',
    E2E_AUTH_RESPONSE = 'e2e_auth_response',

    VALIDATE_TOKEN = 'validate_token',
    VALIDATE_TOKEN_RESULT = 'validate_token_result',

    CLIENT_REPORT = 'client_report',
    PROFILE_RESPONSE = 'profile_response',
    ACCESS_DENIED = 'access_denied'
}

// ----------- base types ------------

export type RelayMessage = {
    type: MSG.RELAY;
    to: string;
    inner: InnerMessage;
};

export type InnerMessage =
    | HelloMsg
    | HelloReplyMsg
    | AuthRequestMsg
    | AuthResponseMsg
    | ValidateTokenMsg
    | ValidateTokenResultMsg;

// ----------- specific messages ------------

export type HelloMsg = {
    type: MSG.E2E_HELLO;
    clientPublicKeyPem: string;
};

export type HelloReplyMsg = {
    type: MSG.E2E_HELLO_REPLY;
    agentPublicKeyPem: string;
};

export type AuthRequestMsg = {
    type: MSG.E2E_AUTH_REQUEST;
    payload: EncryptedPayload;
};

export type AuthResponseMsg = {
    type: MSG.E2E_AUTH_RESPONSE;
    payload: EncryptedPayload;
};

export type ValidateTokenMsg = {
    type: MSG.VALIDATE_TOKEN;
    token: string;
};

export type ValidateTokenResultMsg = {
    type: MSG.VALIDATE_TOKEN_RESULT;
    ok: boolean;
    claims?: any;
};

// ----------- crypto payload ------------

export type EncryptedPayload = {
    iv: string;
    ciphertext: string;
    tag: string;
};

// ----------- helpers ------------

//Converts the object into a JSON string to send it through webSocket
export function encode(msg: unknown): string {
    return JSON.stringify(msg);
}
//Converts message into object
export function decode<T = any>(raw: WebSocket.RawData): T {
    return JSON.parse(raw.toString());
}