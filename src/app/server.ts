import { WebSocketServer, WebSocket } from 'ws';
import { MSG, encode, decode } from '../shared/protocol.js';

//Client with id and the Socket
type RegisteredClient = {
    id: string;
    socket: WebSocket;
};

const wss = new WebSocketServer({ port: 5000 }); //Creates a web socket where agent and client will connect

let agentSocket: WebSocket | null = null; //Agents connection to the web Socket
let clientCounter = 0;

const clients = new Map<string, RegisteredClient>(); //Saves all the connected clients

wss.on('connection', (ws) => {
    let currentClientId: string | null = null;
    let isAgent = false;

    ws.on('message', (raw) => {
        const msg = decode<any>(raw);

        if (msg.type == MSG.REGISTER){
            if (msg.role == 'agent'){
                agentSocket = ws;
                isAgent = true;
                console.log('[app] agent registered');
                return;
            }
        }
        if (msg.role == 'client'){
            currentClientId = `client-${++clientCounter}`;
            clients.set(currentClientId, {
                id: currentClientId,
                socket: ws,
            });
            ws.send(
                encode({
                 type: 'registered',
                 clientId: currentClientId
                })
            );
            console.log(`[app] client registered as ${currentClientId}`);
            return;
        }

        if (msg.type == MSG.CLIENT_REPORT){
            if (!currentClientId){
                console.warn('[app] CLIENT_REPORT received from unknown client');
                return;
            }
            if (!agentSocket){
                console.warn('[app] no agent connected');

                ws.send(
                    encode({
                        type: MSG.ACCESS_DENIED,
                        reason: 'No agent connected'
                    })
                );
                return;
            }
            console.log(`[app] received token report from ${currentClientId}`);
            console.log('[app] asking agent to validate token');

            agentSocket.send(
                encode({
                    type: MSG.RELAY,
                    from: currentClientId,
                    inner: {
                        type: MSG.VALIDATE_TOKEN,
                        token: msg.token
                    }
                })
            );
            return;
        }
        if (msg.type === MSG.RELAY) {
            const senderId = isAgent ? 'agent' : currentClientId;

            if (!senderId) {
                console.warn('[app] relay received from unregistered socket');
                return;
            }
            if (msg.to == 'agent'){
                if (!agentSocket){
                    console.warn('[app] no agent connected');
                    return;
                }
                agentSocket.send(
                    encode({
                        type: MSG.RELAY,
                        from: senderId,
                        inner: msg.inner
                    })
                );
                return;
            }
            //AGENT -> APP WITH TOKEN Validation result. Inside msg.inner = VALIDATE TOKEN RESULT
            if ( isAgent && msg.inner?.type === MSG.VALIDATE_TOKEN_RESULT){
                const clientId = msg.to;
                const targetClient = clients.get(clientId);

                if(!targetClient){
                    console.warn(`[app] client not found for validation result: ${clientId}`);
                    return;
                }
                if (msg.inner.ok){
                    console.log(`[app] token valid for ${clientId}`);
                    console.log('[app] sending profile to client');

                    targetClient.socket.send(
                        encode({
                            type: MSG.PROFILE_RESPONSE,
                            profile: {
                                mouseMapping: 'left-handed',
                                keyboard: 'EU'
                            }
                        })
                    );
                } else {
                    console.log(`[app] token invalid for ${clientId}`);

                    targetClient.socket.send(
                        encode({
                            type: MSG.ACCESS_DENIED,
                            reason: 'Invalid token'
                        })
                    );
                }
                return;
            }
            //AGENT TO CLIENT -> NORMAL RELAY
            const targetClient = clients.get(msg.to);

            if (!targetClient) {
                console.warn(`[app] client not found: ${msg.to}`);
                return;
            }

            targetClient.socket.send(
                encode({
                    type: MSG.RELAY,
                    from: senderId,
                    inner: msg.inner
                })
            );

            return;
        }
    });

    ws.on('close', () => {
        if (currentClientId) {
            clients.delete(currentClientId);
            console.log(`[app] client disconnected: ${currentClientId}`);
        }

        if (ws === agentSocket) {
            agentSocket = null;
            console.log('[app] agent disconnected');
        }
    });
});

console.log('[app] listening on ws://localhost:5000');