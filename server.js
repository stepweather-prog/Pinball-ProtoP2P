const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const SESSION_TTL = 30 * 60 * 1000;
const MAX_SESSIONS = 50;
const CLEANUP_INTERVAL = 30 * 1000;
const BEACON_TTL = 90 * 1000; // 90 секунд — как в клиенте

const sessions = {};
const beacons = {};

function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function generateSessionId() { return crypto.randomBytes(16).toString('hex'); }

function cleanupAll() {
    const now = Date.now();
    for (const id of Object.keys(beacons)) {
        if ((now - beacons[id].createdAt) > BEACON_TTL) delete beacons[id];
    }
    for (const id of Object.keys(sessions)) {
        if ((now - sessions[id].createdAt) > SESSION_TTL) delete sessions[id];
    }
    const remaining = Object.keys(sessions);
    if (remaining.length > MAX_SESSIONS) {
        const sorted = remaining.sort((a,b) => sessions[a].createdAt - sessions[b].createdAt);
        for (const id of sorted.slice(0, remaining.length - MAX_SESSIONS)) delete sessions[id];
    }
}

function touchSession(id) { if (sessions[id]) sessions[id].createdAt = Date.now(); }

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    const params = url.searchParams;
    
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); if (body.length > 100000) { res.writeHead(413); res.end(JSON.stringify({ error: 'payload_too_large' })); } });
    
    req.on('end', () => {
        let p = {};
        if (body) { try { p = JSON.parse(body); } catch(e) { res.writeHead(400); res.end(JSON.stringify({ error: 'invalid_json' })); return; } }
        
        // ============ МАЯК (BEACON) — ПРИНИМАЕТ tempKeyHash ============
        if (req.method === 'POST' && path === '/beacon') {
            // Пробуем оба варианта: tempKeyHash (новый клиент) или tempKey (старый)
            const keyHash = p.tempKeyHash || (p.tempKey ? crypto.createHash('sha256').update(p.tempKey).digest('hex') : null);
            if (!keyHash) { res.writeHead(400); res.end(JSON.stringify({ error: 'missing_tempKeyHash' })); return; }
            
            // Проверяем — нет ли уже маяка с таким хешем
            for (const id of Object.keys(beacons)) {
                if (beacons[id].tempKeyHash === keyHash) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ sessionId: id, matched: false }));
                    return;
                }
            }
            
            const sid = generateSessionId();
            beacons[sid] = { tempKeyHash: keyHash, sessionId: sid, createdAt: Date.now(), matched: false };
            // Сразу создаём сессию для отправки сообщений
            sessions[sid] = { createdAt: Date.now(), messages: [], matched: true };
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ sessionId: sid }));
        }
        
        // ============ ПОИСК МАЯКА — ПРИНИМАЕТ tempKey ============
        else if (req.method === 'POST' && path === '/find') {
            // Ищем по tempKey (хешируем для сравнения) или по tempKeyHash
            const findHash = p.tempKeyHash || (p.tempKey ? crypto.createHash('sha256').update(p.tempKey).digest('hex') : null);
            if (!findHash) { res.writeHead(400); res.end(JSON.stringify({ error: 'missing_tempKey' })); return; }
            
            let found = null;
            for (const id of Object.keys(beacons)) {
                if (beacons[id].tempKeyHash === findHash && !beacons[id].matched) {
                    beacons[id].matched = true;
                    found = beacons[id];
                    break;
                }
            }
            
            if (found) {
                // Сессия уже создана в /beacon — просто отмечаем matched
                if (!sessions[found.sessionId]) {
                    sessions[found.sessionId] = { createdAt: Date.now(), messages: [], matched: true };
                } else {
                    sessions[found.sessionId].matched = true;
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ sessionId: found.sessionId, status: 'matched' }));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: 'waiting' }));
            }
        }
        
        // ============ ПРОВЕРКА СТАТУСА МАЯКА ============
        else if (req.method === 'GET' && path === '/beacon') {
            const id = params.get('id');
            if (!id) { res.writeHead(200); res.end(JSON.stringify({ matched: false })); return; }
            // Проверяем и в beacons, и в sessions
            const b = beacons[id];
            const s = sessions[id];
            const matched = (b && b.matched) || (s && s.matched) || false;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ matched, sessionId: id }));
        }
        
        // ============ ОТПРАВКА СООБЩЕНИЯ ============
        else if (req.method === 'POST' && path === '/message') {
            if (!p.sessionId || !p.packet) { res.writeHead(400); res.end(JSON.stringify({ error: 'missing_params' })); return; }
            
            // Авто-создание сессии если её нет (для совместимости)
            if (!sessions[p.sessionId]) {
                sessions[p.sessionId] = { createdAt: Date.now(), messages: [], matched: true };
            }
            
            touchSession(p.sessionId);
            sessions[p.sessionId].messages.push({ packet: p.packet, time: Date.now() });
            if (sessions[p.sessionId].messages.length > 100) {
                sessions[p.sessionId].messages = sessions[p.sessionId].messages.slice(-50);
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ok' }));
        }
        
        // ============ ПОЛУЧЕНИЕ СООБЩЕНИЙ ============
        else if (req.method === 'GET' && path === '/message') {
            const id = params.get('id'), since = parseInt(params.get('since')) || 0;
            if (!id || !sessions[id]) { res.writeHead(200); res.end(JSON.stringify({ messages: [] })); return; }
            touchSession(id);
            const msgs = sessions[id].messages.filter(m => m.time > since);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ messages: msgs }));
        }
        
        // ============ PING ============
        else if (req.method === 'GET' && path === '/ping') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
        }
        
        // ============ 404 ============
        else { res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); }
    });
});

setInterval(cleanupAll, CLEANUP_INTERVAL);
server.listen(PORT, () => console.log('RobinHood Message Server on port ' + PORT));
