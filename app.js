// The Python profile owns durable history; reconnecting this view restores its snapshot.
let state = {peers: [], messages: []};
let activeContactId = null;
let uiSocket = null;
let reconnectDelay = 1000;
let relayStatus = 'Connecting to relay';
let sharingPeer = null;
let watchId = null;
let shareTimer = null;
let locationTimer = null;
let latestPosition = null;
let lastTyping = 0;
let typingTimer = null;
const presence = new Map();
const typing = new Map();
const locations = new Map();
const el = id => document.getElementById(id);

function notice(text) { el('notice').textContent = text; }
function send(data) {
    if (!uiSocket || uiSocket.readyState !== WebSocket.OPEN) {
        notice('Local client is disconnected. Your unsent draft is still in the input.');
        return false;
    }
    uiSocket.send(JSON.stringify(data));
    return true;
}

async function connect() {
    try {
        // Refresh the HttpOnly session cookie if the local Python process restarted.
        await fetch('/', {cache: 'no-store'});
        uiSocket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
        uiSocket.onopen = () => { reconnectDelay = 1000; };
        uiSocket.onmessage = event => {
            const data = JSON.parse(event.data);
            if (data.type === 'snapshot') {
                state = data;
                if (!activeContactId && state.peers.length) activeContactId = state.peers[0].user_id;
                el('my-identity').textContent = `My ID: ${data.user_id || 'registering…'} | Fingerprint: ${data.fingerprint}`;
                render();
                markRead();
            } else if (data.type === 'connection') {
                relayStatus = data.text;
                el('connection-status').textContent = `Local client connected · ${relayStatus}`;
                if (relayStatus !== 'Connected') { presence.clear(); typing.clear(); renderPresence(); }
            } else if (data.type === 'error') {
                notice(data.text);
            } else if (data.type === 'presence') {
                presence.set(data.user_id, {...data, received: Date.now()});
                renderPresence();
            } else if (data.type === 'typing_start' || data.type === 'typing_stop') {
                // Lost stop events cannot leave a contact shown as typing forever.
                typing.set(data.sender_id, data.type === 'typing_start' ? Date.now() + 5000 : 0);
                renderPresence();
            } else if (data.type === 'distance_update') {
                locations.set(data.sender_id, data);
                renderRadar();
            } else if (data.type === 'location_stop') {
                locations.delete(data.sender_id);
                renderRadar();
            }
        };
        uiSocket.onclose = () => {
            stopSharing();
            presence.clear(); typing.clear();
            el('connection-status').textContent = 'Local client disconnected · reconnecting…';
            renderPresence();
            const wait = reconnectDelay + Math.random() * reconnectDelay * .2;
            reconnectDelay = Math.min(30000, reconnectDelay * 2);
            setTimeout(connect, wait);
        };
        uiSocket.onerror = () => { /* onclose owns the single reconnect timer. */ };
    } catch (_) {
        el('connection-status').textContent = 'Local client unavailable · reconnecting…';
        setTimeout(connect, reconnectDelay);
        reconnectDelay = Math.min(30000, reconnectDelay * 2);
    }
}

function contactName(id) {
    const peer = state.peers.find(p => p.user_id === id);
    return peer?.alias || id;
}
function promptNewContact() {
    const value = prompt('Enter your friend’s user ID:');
    if (!value) return;
    const id = value.trim();
    if (!/^usr_[0-9a-f]{16}$/.test(id)) return notice('That does not look like a user ID.');
    if (send({type: 'add_target', recipient_id: id})) {
        switchContact(id);
        notice('Contact added. Compare fingerprints with your friend before trusting this identity.');
    }
}
function switchContact(id) {
    // Switching conversations stops sharing instead of silently changing its recipient.
    if (activeContactId !== id) {
        stopSharing();
        if (activeContactId) send({type: 'typing_stop', recipient_id: activeContactId});
    }
    activeContactId = id;
    render();
    markRead();
    send({type: 'presence', recipient_id: id});
}
function render() {
    el('target-bar').replaceChildren();
    for (const peer of state.peers) {
        const tab = document.createElement('button');
        tab.className = 'target-tab' + (peer.user_id === activeContactId ? ' active' : '');
        // Verification is local and visible; a first-use key is not claimed to be verified.
        tab.textContent = contactName(peer.user_id) + (peer.verified ? ' ✓' : ' · unverified');
        tab.onclick = () => switchContact(peer.user_id);
        el('target-bar').append(tab);
    }
    el('current-target').textContent = activeContactId ? contactName(activeContactId) : 'NO TARGET';
    el('msg-input').disabled = !activeContactId;
    el('send-btn').disabled = !activeContactId;
    const container = el('messages-container');
    container.replaceChildren();
    for (const msg of state.messages.filter(m => m.peer === activeContactId)) {
        const bubble = document.createElement('div');
        bubble.className = `msg-bubble ${msg.direction}`;
        // All peer/bot text is rendered as text nodes, eliminating HTML injection.
        bubble.append(document.createTextNode(msg.text));
        if (msg.media && /^[0-9a-f-]{36}$/.test(msg.media.id)) {
            // Use authenticated local URLs and native image/audio elements, never HTML embeds.
            const preview = document.createElement(msg.media.mime.startsWith('image/') ? 'img' : 'audio');
            preview.className = 'attachment-preview';
            preview.src = `/files/${msg.media.id}`;
            if (msg.media.mime.startsWith('image/')) { preview.alt = msg.media.name; preview.loading = 'lazy'; }
            else { preview.controls = true; preview.preload = 'none'; }
            bubble.append(preview);
        }
        if (msg.direction === 'sent') {
            const status = document.createElement('div');
            status.className = 'msg-meta';
            // Surface relay policy errors beside the affected message, not only in a banner.
            status.textContent = ({pending: '◷ Pending', failed: 'Not sent', sent: '✓ Saved by relay', delivered: '✓✓ Delivered', read: '✓✓ Read'})[msg.status] || msg.status;
            if (msg.error) status.textContent += ` · ${msg.error}`;
            bubble.append(status);
            if (msg.status === 'failed') {
                const retry = document.createElement('button');
                retry.className = 'btn-target';
                retry.textContent = 'Retry';
                retry.onclick = () => send({type: 'retry', recipient_id: msg.peer, msg_id: msg.id});
                bubble.append(retry);
            }
        }
        container.append(bubble);
    }
    container.scrollTop = container.scrollHeight;
    renderPresence();
    renderRadar();
}
function sendPayload() {
    const input = el('msg-input');
    const text = input.value.trim();
    if (!text || !activeContactId) return;
    // UUIDs remain stable through the client's durable retry path.
    if (send({type: 'chat', recipient_id: activeContactId, msg_id: crypto.randomUUID(), text})) {
        input.value = '';
        send({type: 'typing_stop', recipient_id: activeContactId});
    }
}
function handleEnter(event) {
    if (event.key === 'Enter' && !event.isComposing) { event.preventDefault(); sendPayload(); }
}
function markRead() {
    if (document.hasFocus() && !document.hidden && activeContactId && state.messages.some(
        m => m.peer === activeContactId && m.direction === 'received' && m.status !== 'read')) {
        send({type: 'read', recipient_id: activeContactId});
    }
}
window.addEventListener('focus', markRead);
document.addEventListener('visibilitychange', markRead);
function renameContact() {
    if (!activeContactId) return;
    const alias = prompt('Local contact name (blank restores the user ID):', contactName(activeContactId));
    if (alias !== null) send({type: 'alias', recipient_id: activeContactId, alias});
}
function verifyContact() {
    const peer = state.peers.find(p => p.user_id === activeContactId);
    if (!peer?.fingerprint) return notice('Waiting for this contact’s public key.');
    if (confirm(`Compare with your friend over another trusted channel.\n\nYour fingerprint:\n${state.fingerprint}\n\nTheir fingerprint:\n${peer.fingerprint}\n\n${peer.verified ? 'Previously verified. ' : ''}Do they match?`)) {
        send({type: 'verify', recipient_id: peer.user_id, fingerprint: peer.fingerprint});
        notice('Contact fingerprint marked verified on this device.');
    }
}
function renderPresence() {
    const info = presence.get(activeContactId);
    el('presence-status').textContent = info && Date.now() - info.received < 25000
        ? (info.online ? 'Online' : `Offline${info.last_seen ? ' · seen ' + new Date(info.last_seen * 1000).toLocaleTimeString() : ''}`)
        : 'Presence unknown';
    el('typing-status').textContent = (typing.get(activeContactId) || 0) > Date.now() ? 'Typing…' : '';
}
function sendTyping() {
    if (!activeContactId) return;
    if (Date.now() - lastTyping > 2000) {
        send({type: 'typing_start', recipient_id: activeContactId});
        lastTyping = Date.now();
    }
    clearTimeout(typingTimer);
    const peer = activeContactId;
    typingTimer = setTimeout(() => send({type: 'typing_stop', recipient_id: peer}), 2500);
}
function toggleRadar() {
    if (!el('radar-toggle').checked) return stopSharing();
    if (!activeContactId || !navigator.geolocation) {
        el('radar-toggle').checked = false;
        return notice('Select a contact and use a browser with location support.');
    }
    if (!confirm(`Share your location with ${contactName(activeContactId)} for up to 15 minutes? Switching contacts stops sharing.`)) {
        el('radar-toggle').checked = false;
        return;
    }
    sharingPeer = activeContactId;
    send({type: 'location_start', recipient_id: sharingPeer});
    el('radar-panel').classList.remove('collapsed');
    const update = () => {
        if (sharingPeer && latestPosition) send({type: 'location_update', recipient_id: sharingPeer,
                                                lat: latestPosition.latitude, lon: latestPosition.longitude});
    };
    watchId = navigator.geolocation.watchPosition(position => {
        latestPosition = position.coords;
        update();
    }, error => { notice(`Location unavailable: ${error.message}`); stopSharing(); },
    {enableHighAccuracy: true, maximumAge: 10000, timeout: 15000});
    locationTimer = setInterval(update, 5000);
    shareTimer = setTimeout(stopSharing, 15 * 60 * 1000);
}
function stopSharing() {
    if (watchId !== null) navigator.geolocation.clearWatch(watchId);
    clearTimeout(shareTimer); clearInterval(locationTimer);
    if (sharingPeer && uiSocket?.readyState === WebSocket.OPEN) send({type: 'location_stop', recipient_id: sharingPeer});
    sharingPeer = null; watchId = null; latestPosition = null;
    el('radar-toggle').checked = false;
    el('radar-panel').classList.add('collapsed');
}
function renderRadar() {
    const data = locations.get(activeContactId);
    const blip = document.querySelector('.radar-blip');
    if (!data || Date.now() / 1000 > Math.min(data.expires, data.updated + 30)) {
        el('radar-distance').textContent = 'No recent shared location';
        blip.style.display = 'none';
        return;
    }
    // Use geographic bearing (north at the top), never a decorative ID-derived angle.
    blip.style.display = '';
    const angle = data.bearing * Math.PI / 180;
    const radius = Math.min(42, data.distance * 15);
    blip.style.left = `calc(50% + ${Math.sin(angle) * radius}% - 4px)`;
    blip.style.top = `calc(50% - ${Math.cos(angle) * radius}% - 4px)`;
    el('radar-distance').textContent = `${data.distance.toFixed(2)} mi · ${Math.round(data.bearing)}° · updated ${new Date(data.updated * 1000).toLocaleTimeString()}`;
}
setInterval(() => {
    renderPresence(); renderRadar();
}, 1000);
setInterval(() => {
    if (activeContactId && uiSocket?.readyState === WebSocket.OPEN && relayStatus === 'Connected')
        send({type: 'presence', recipient_id: activeContactId});
}, 10000);
window.addEventListener('pagehide', stopSharing);
connect();

// Uploads go to the authenticated local bridge; encryption and relay retries stay in Python.
let uploadBusy = false;
let recorder = null;
let recordingStream = null;
let recordingTimer = null;
let voiceBlob = null;
let voiceURL = null;
let voicePeer = null;
// A generation prevents late microphone/stop callbacks from reviving cancelled drafts.
let voiceGeneration = 0;

function chooseImage() { el('image-file').click(); }
function uploadMedia(blob, name, recipient, onSaved = () => {}) {
    if (uploadBusy || !recipient) return notice('Select a contact and wait for any current upload.');
    if (!blob.size || blob.size > 5 * 1024 * 1024) return notice('Files must be between 1 byte and 5 MiB.');
    uploadBusy = true;
    const request = new XMLHttpRequest();
    request.open('POST', `/upload?recipient_id=${encodeURIComponent(recipient)}&name=${encodeURIComponent(name)}`);
    request.setRequestHeader('Content-Type', blob.type || 'application/octet-stream');
    request.timeout = 45000;
    request.upload.onprogress = e => { if (e.lengthComputable) notice(`Saving locally: ${Math.round(e.loaded / e.total * 100)}%`); };
    request.onload = () => {
        uploadBusy = false;
        if (request.status === 200) onSaved();
        notice(request.status === 200 ? 'File saved locally. Encrypted relay delivery will retry if needed.' : 'File rejected: ' + request.responseText);
    };
    request.onerror = request.ontimeout = () => { uploadBusy = false; notice('Could not save the file to the local client. Check your connection and try again.'); };
    request.send(blob);
}
function selectedImage(event) {
    const file = event.target.files[0];
    if (file) uploadMedia(file, file.name, activeContactId);
    event.target.value = '';
}
async function recordVoice() {
    if (recorder?.state === 'recording') { recorder.stop(); return; }
    if (!activeContactId) return notice('Select a contact first.');
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined')
        return notice('Voice recording is not supported by this browser.');
    cancelVoice();
    const generation = voiceGeneration;
    voicePeer = activeContactId;
    el('record-btn').disabled = true;
    try {
        const stream = await navigator.mediaDevices.getUserMedia({audio: true});
        if (generation !== voiceGeneration) { stream.getTracks().forEach(t => t.stop()); return; }
        recordingStream = stream;
        const mime = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4'].find(t => MediaRecorder.isTypeSupported(t));
        if (!mime) throw new Error('No supported recording format');
        const currentRecorder = recorder = new MediaRecorder(stream, {mimeType: mime, audioBitsPerSecond: 96000});
        const chunks = [];
        let bytes = 0;
        recorder.ondataavailable = e => {
            if (e.data.size) { chunks.push(e.data); bytes += e.data.size; }
            if (bytes > 5 * 1024 * 1024 && currentRecorder.state === 'recording') currentRecorder.stop();
        };
        recorder.onstop = () => {
            stream.getTracks().forEach(t => t.stop());
            if (generation !== voiceGeneration) return;
            clearTimeout(recordingTimer);
            el('record-btn').textContent = 'VOICE';
            voiceBlob = new Blob(chunks, {type: mime});
            if (voiceBlob.size > 5 * 1024 * 1024) { cancelVoice(); return notice('Recording exceeded 5 MiB. Try a shorter note.'); }
            voiceURL = URL.createObjectURL(voiceBlob);
            el('voice-preview').src = voiceURL;
            el('voice-draft').hidden = false;
            el('voice-recipient').textContent = `Voice note to ${contactName(voicePeer)}`;
        };
        recorder.onerror = () => {
            stream.getTracks().forEach(t => t.stop());
            if (generation === voiceGeneration) { cancelVoice(); notice('Recording failed. Please try again.'); }
        };
        recorder.start(1000);
        recordingTimer = setTimeout(() => { if (currentRecorder.state === 'recording') currentRecorder.stop(); }, 120000);
        el('record-btn').textContent = 'STOP';
        notice(`Recording for ${contactName(voicePeer)} · maximum 2 minutes. Stop to preview before sending.`);
    } catch (_) {
        if (generation !== voiceGeneration) return;
        cancelVoice();
        notice('Microphone unavailable or recording format unsupported. Check browser permissions.');
    } finally { if (generation === voiceGeneration) el('record-btn').disabled = false; }
}
function cancelVoice() {
    voiceGeneration++;
    clearTimeout(recordingTimer);
    if (recorder?.state === 'recording') recorder.stop();
    recordingStream?.getTracks().forEach(t => t.stop());
    if (voiceURL) URL.revokeObjectURL(voiceURL);
    voiceBlob = null; voiceURL = null;
    el('voice-draft').hidden = true;
    el('voice-preview').removeAttribute('src');
    el('record-btn').textContent = 'VOICE';
    el('record-btn').disabled = false;
}
function sendVoice() {
    if (voiceBlob && !uploadBusy) {
        const extension = voiceBlob.type.includes('mp4') ? 'm4a' : voiceBlob.type.includes('ogg') ? 'ogg' : 'webm';
        // Keep the preview after a failed local upload so the user can retry it.
        const generation = voiceGeneration;
        uploadMedia(voiceBlob, `voice-note.${extension}`, voicePeer, () => {
            if (generation === voiceGeneration) cancelVoice();
        });
    }
}
window.addEventListener('pagehide', cancelVoice);
