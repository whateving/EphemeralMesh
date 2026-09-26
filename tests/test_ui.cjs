// Exercise the real UI script with a minimal DOM that rejects unsafe HTML writes.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');

class Element {
    constructor() { this.children = []; this.style = {}; this.value = ''; this.classList = {add() {}, remove() {}}; }
    set innerHTML(_) { throw new Error('Untrusted HTML rendering is forbidden'); }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren() { this.children = []; }
    removeAttribute(name) { delete this[name]; }
}
async function ui(overrides = {}) {
    const elements = new Map();
    const sockets = [];
    const timers = [];
    class Socket {
        static OPEN = 1;
        constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
        send(payload) { this.sent.push(JSON.parse(payload)); }
    }
    const document = {
        getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
        createElement() { return new Element(); },
        createTextNode(text) { return {text}; },
        querySelector() { return new Element(); },
        hasFocus() { return false; },
        addEventListener() {},
    };
    const context = vm.createContext({document, window: {addEventListener() {}}, crypto,
        location: {protocol: 'http:', host: '127.0.0.1:8081'},
        navigator: {}, WebSocket: Socket, fetch: async () => ({}),
        setTimeout(fn, delay) { timers.push({fn, delay}); }, clearTimeout() {},
        setInterval() {}, clearInterval() {}, prompt() {}, confirm() { return false; }, ...overrides});
    vm.runInContext(fs.readFileSync(require('node:path').join(__dirname, '../app.js'), 'utf8'), context);
    await new Promise(resolve => setImmediate(resolve));
    return {context, document, socket: sockets[0], timers};
}

test('Hostile chat and alias strings are rendered literally; snapshots do not duplicate history', async () => {
    const {document, socket} = await ui();
    const attack = '<img src=x onerror=alert(1)><b>not HTML</b>';
    const snapshot = {type: 'snapshot', user_id: 'usr_aaaaaaaaaaaaaaaa', fingerprint: 'abc',
        peers: [{user_id: 'usr_bbbbbbbbbbbbbbbb', alias: attack}],
        messages: [{peer: 'usr_bbbbbbbbbbbbbbbb', direction: 'received', text: attack, status: 'delivered'}]};
    socket.onmessage({data: JSON.stringify(snapshot)});
    socket.onmessage({data: JSON.stringify(snapshot)});
    const container = document.getElementById('messages-container');
    assert.equal(container.children.length, 1);
    assert.equal(container.children[0].children[0].text, attack);
    assert.equal(document.getElementById('current-target').textContent, attack);
});

test('Sending while the local bridge is disconnected preserves the draft', async () => {
    const {context, document, socket} = await ui();
    socket.onmessage({data: JSON.stringify({type: 'snapshot', peers: [{user_id: 'usr_bbbbbbbbbbbbbbbb'}], messages: []})});
    document.getElementById('msg-input').value = 'Keep this draft';
    socket.readyState = 3;
    context.sendPayload();
    assert.equal(document.getElementById('msg-input').value, 'Keep this draft');
    assert.equal(socket.sent.length, 0);
});

test('Local socket closure schedules reconnect and stops sharing', async () => {
    const {socket, timers, document} = await ui();
    socket.readyState = 3;
    socket.onclose();
    assert.equal(timers.length, 1);
    assert.equal(document.getElementById('radar-toggle').checked, false);
    assert.match(document.getElementById('connection-status').textContent, /reconnecting/);
});

test('A rejected message shows its reason and retries with the original ID', async () => {
    const {document, socket} = await ui();
    const peer = 'usr_bbbbbbbbbbbbbbbb';
    const id = '08d17f24-c59c-4521-8dcb-76a3c0e21b62';
    socket.onmessage({data: JSON.stringify({type: 'snapshot', peers: [{user_id: peer}],
        messages: [{id, peer, direction: 'sent', text: 'Keep me', status: 'failed', error: 'Message too large'}]})});
    const bubble = document.getElementById('messages-container').children[0];
    assert.match(bubble.children[1].textContent, /Not sent.*Message too large/);
    const retry = bubble.children[2];
    assert.equal(retry.textContent, 'Retry');
    retry.onclick();
    assert.deepEqual(socket.sent[0], {type: 'retry', recipient_id: peer, msg_id: id});
});

// Untrusted filenames remain labels, and only local authenticated media URLs render.
test('Attachments render local image/audio previews without injecting filenames', async () => {
    const {document, socket} = await ui();
    const peer = 'usr_bbbbbbbbbbbbbbbb';
    const id = '08d17f24-c59c-4521-8dcb-76a3c0e21b62';
    socket.onmessage({data: JSON.stringify({type: 'snapshot', peers: [{user_id: peer}], messages: [
        {peer, direction: 'received', text: '<script>bad</script>', media: {id, mime: 'image/png', name: '<svg onload=bad>'}},
        {peer, direction: 'received', text: 'Voice', media: {id, mime: 'audio/webm', name: 'note.webm'}}
    ]})});
    const bubbles = document.getElementById('messages-container').children;
    assert.equal(bubbles[0].children[1].src, `/files/${id}`);
    assert.equal(bubbles[0].children[1].alt, '<svg onload=bad>');
    assert.equal(bubbles[1].children[1].controls, true);
});

test('Late stop callback cannot revive a cancelled voice note or stop the new microphone', async () => {
    const recordings = [], tracks = [];
    class Recorder {
        static isTypeSupported() { return true; }
        constructor() { recordings.push(this); }
        start() { this.state = 'recording'; }
        stop() { this.state = 'inactive'; }
    }
    const {context, socket, document} = await ui({MediaRecorder: Recorder, Blob,
        URL: {createObjectURL() { return 'blob:test'; }, revokeObjectURL() {}},
        navigator: {mediaDevices: {async getUserMedia() {
            const track = {stopped: false, stop() { this.stopped = true; }};
            tracks.push(track); return {getTracks() { return [track]; }};
        }}}
    });
    socket.onmessage({data: JSON.stringify({type: 'snapshot', peers: [{user_id: 'usr_bbbbbbbbbbbbbbbb'}], messages: []})});
    await context.recordVoice();
    context.cancelVoice();
    await context.recordVoice();
    recordings[0].onstop();
    assert.equal(document.getElementById('voice-draft').hidden, true);
    assert.equal(tracks[0].stopped, true);
    assert.equal(tracks[1].stopped, false);
    context.cancelVoice();
});
