
const originalFetch = window.fetch;
window.fetch = function() {
    if (arguments[0].toString().startsWith('/api')) {
        if (!arguments[1]) arguments[1] = {};
        arguments[1].credentials = "same-origin";
    }
    return originalFetch.apply(this, arguments);
};

// secNet Chat — minimal vanilla JS client

const agentBase = () => `http://127.0.0.1:${new URLSearchParams(window.location.search).get("port") || window.__agentPort || 48271}`;

// State
let me = null;
let socket = null;
let directory = [];
let groups = [];
let activeChannel = null; // {type: "general"|"group"|"dm", id, name}
let messageHistory = {}; // channel key -> [{sender, text, isFile, ...}]

// DOM shortcuts
const $ = (id) => document.getElementById(id);
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ---- Agent calls -------------------------------------------------------- //

async function agent(path, body) {
  const r = await fetch(agentBase() + path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  });
  const result = await r.json();
  if (!r.ok) throw new Error(result.error || "crypto agent error");
  return result;
}

// ---- Auth --------------------------------------------------------------- //

async function authenticate() {
  setStatus("Connecting…");
  const cr = await fetch("/api/auth/challenge?port=" + (new URLSearchParams(window.location.search).get("port") || window.__agentPort || 48271));
  const challenge = await cr.json();
  if (!cr.ok) throw new Error(challenge.error || "VPN device not authenticated");
  window.__agentPort = challenge.agent_port;

  const signed = await agent("/v1/sign", {challenge: challenge.challenge});
  const vr = await fetch("/api/auth/verify", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      challenge_id: challenge.challenge_id,
      device_tag: challenge.device_tag,
      signature: signed.signature,
    }),
  });
  const verified = await vr.json();
  if (!vr.ok) throw new Error(verified.error || "auth rejected");

  me = await (await fetch("/api/me")).json();
  $("myTag").textContent = (me.username || "") + " " + me.device_tag.slice(0, 12) + "…";
  $("usernameInput").value = me.username || "";
  $("login").style.display = "none";
  $("app").style.display = "flex";

  await loadDirectory();
  await loadGroups();
  await syncGroupState("general");
  connectSocket();
  renderSidebar();
  openChannel({type: "general", id: "general", name: "#general"});
  await initializeGroup("general").catch(e => setStatus("General group: " + e.message));
}

// ---- Directory ---------------------------------------------------------- //

async function loadDirectory() {
  const r = await fetch("/api/directory");
  if (!r.ok) return;
  directory = await r.json();
  renderDirectory();
}

async function loadGroups() {
  const r = await fetch("/api/groups");
  if (!r.ok) return;
  groups = await r.json();
}

function renderDirectory() {
  const list = $("dirList");
  list.replaceChildren();
  for (const d of directory) {
    const el = document.createElement("div");
    el.className = "dir-entry";
    const status = d.online ? '<span class="online">●</span>' : '<span class="offline">○</span>';
    el.innerHTML = `${status} ${escHtml(d.username || "(unnamed)")}<br><span style="color:#555;font-size:11px">${d.device_tag.slice(0,14)}…</span>`;
    if (d.device_tag !== me.device_tag && d.encryption_public_key) {
      el.onclick = () => openDM(d);
    }
    list.appendChild(el);
  }
}

// ---- Sidebar ------------------------------------------------------------ //

function renderSidebar() {
  const list = $("channelList");
  list.replaceChildren();

  // General channel
  addChannelItem(list, {type: "general", id: "general", name: "#general"});

  // Named groups
  for (const g of groups) {
    addChannelItem(list, {type: "group", id: g.group_id, name: "#" + g.name});
  }

  // DM channels (from existing messageHistory keys)
  for (const key of Object.keys(messageHistory)) {
    if (key.startsWith("dm:")) {
      const tag = key.slice(3);
      const d = directory.find(x => x.device_tag === tag);
      const name = d ? (d.username || tag.slice(0, 12) + "…") : tag.slice(0, 12) + "…";
      addChannelItem(list, {type: "dm", id: tag, name});
    }
  }
}

function addChannelItem(container, ch) {
  const el = document.createElement("div");
  el.className = "channel-item " + ch.type;
  el.textContent = ch.name;
  const key = channelKey(ch);
  if (activeChannel && channelKey(activeChannel) === key) el.classList.add("active");
  el.onclick = () => openChannel(ch);
  container.appendChild(el);
}

function channelKey(ch) {
  return ch.type + ":" + ch.id;
}

// ---- Channel open ------------------------------------------------------- //

function openChannel(ch) {
  activeChannel = ch;
  $("chatTitle").textContent = ch.name;
  $("chatMeta").textContent = ch.type === "group"
    ? (groups.find(g => g.group_id === ch.id)?.members?.length || 0) + " members"
    : "";
  renderMessages();
  renderSidebar();

  // Load history
  if (ch.type === "general") {
    fetch("/api/history/general").then(r => r.json()).then(msgs => {
      if (!messageHistory["general"]) messageHistory["general"] = [];
      // Merge: avoid duplicates
      const existing = new Set(messageHistory["general"].map(m => m._mid));
      for (const m of msgs) {
        if (!existing.has(m.message_id)) {
          decryptAndAppendHistory("general", m, "general");
        }
      }
    }).catch(() => {});
  } else if (ch.type === "group") {
    fetch(`/api/groups/${ch.id}/history`).then(r => r.json()).then(msgs => {
      const key = "group:" + ch.id;
      if (!messageHistory[key]) messageHistory[key] = [];
      const existing = new Set(messageHistory[key].map(m => m._mid));
      for (const m of msgs) {
        if (!existing.has(m.message_id)) {
          decryptAndAppendHistory(key, m, "group");
        }
      }
    }).catch(() => {});
  }
}

function openDM(device) {
  const ch = {type: "dm", id: device.device_tag, name: device.username || device.device_tag.slice(0, 16) + "…"};
  if (!messageHistory["dm:" + device.device_tag]) messageHistory["dm:" + device.device_tag] = [];
  renderSidebar();
  openChannel(ch);
}

// ---- Message rendering -------------------------------------------------- //

function renderMessages() {
  const box = $("messages");
  box.replaceChildren();
  const key = channelKey(activeChannel);
  const msgs = messageHistory[key] || [];
  for (const m of msgs) appendMessageEl(m);
}

function appendMessageEl(m) {
  if (!activeChannel) return;
  const box = $("messages");
  const row = document.createElement("div");
  row.className = "msg";
  const sender = document.createElement("span");
  sender.className = "sender";
  sender.textContent = m.senderLabel || m.sender;
  row.appendChild(sender);
  if (m.isFile) {
    const link = document.createElement("span");
    link.className = "file-link";
    link.textContent = `📎 ${escHtml(m.filename)} (${fmtSize(m.size)})`;
    link.onclick = () => downloadFile(m.fileKey, m.filename, m.fileEnvelope);
    row.appendChild(link);
  } else {
    row.appendChild(document.createTextNode(m.text));
  }
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}

function pushMessage(ch, msg) {
  const key = channelKey(ch);
  if (!messageHistory[key]) messageHistory[key] = [];
  messageHistory[key].push(msg);
  if (activeChannel && channelKey(activeChannel) === key) appendMessageEl(msg);
}

function senderLabel(tag) {
  const d = directory.find(x => x.device_tag === tag);
  return d ? (d.username || tag.slice(0, 12) + "…") : tag.slice(0, 12) + "…";
}

// ---- Decrypt incoming history records ----------------------------------- //

async function decryptAndAppendHistory(histKey, record, type) {
  try {
    let text, isFile = false, fileKey, filename, size, fileEnvelope;
    if (type === "general") {
      const env = record.envelope;
      if (env.type === "file") {
        isFile = true; fileKey = env.file_key; filename = env.filename; size = env.size;
        fileEnvelope = env.file_envelope;
      } else {
        const clear = await agent("/v1/group/decrypt", {envelope: {...env, kind: "group", group_id: "general"}});
        text = new TextDecoder().decode(unb64(clear.plaintext));
      }
    } else if (type === "group") {
      const env = record.envelope;
      if (env.type === "file") {
        isFile = true; fileKey = env.file_key; filename = env.filename; size = env.size;
        fileEnvelope = env.file_envelope;
      } else {
        const clear = await agent("/v1/group/decrypt", {envelope: env});
        text = new TextDecoder().decode(unb64(clear.plaintext));
      }
    }
    const msg = {_mid: record.message_id, sender: record.sender_tag, senderLabel: senderLabel(record.sender_tag), text, isFile, fileKey, filename, size, fileEnvelope};
    if (!messageHistory[histKey]) messageHistory[histKey] = [];
    messageHistory[histKey].push(msg);
    if (activeChannel && channelKey(activeChannel) === histKey) appendMessageEl(msg);
  } catch (_) {}
}

// ---- Group state -------------------------------------------------------- //

async function syncGroupState(groupId) {
  const r = await fetch("/api/mls/state");
  if (!r.ok) return;
  const event = await r.json();
  if (event.payload && event.payload.kind === "tree-group-state-v1") {
    try {
      await agent("/v1/group/install-state", {state: event.payload, own_tag: me.device_tag});
      setStatus(`Group '${groupId}' epoch ${event.payload.epoch} installed.`);
    } catch (e) {
      setStatus(`Group join pending: ${e.message}`);
    }
  }
}

async function initializeGroup(groupId) {
  const dir = await (await fetch("/api/directory")).json();
  const members = dir.filter(x => x.encryption_public_key).map(x => ({
    device_tag: x.device_tag,
    encryption_public_key: x.encryption_public_key,
  }));
  const current = await (await fetch("/api/mls/state")).json();
  const parentEpoch = current.payload ? Number(current.payload.epoch) : 0;
  const state = await agent("/v1/group/create-state", {
    members, own_tag: me.device_tag, epoch: parentEpoch + 1, group_id: groupId,
  });
  const r = await fetch("/api/mls/events", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({group_id: groupId, parent_epoch: parentEpoch, event: state.state}),
  });
  if (!r.ok) throw new Error((await r.json()).error || "group update rejected");
  setStatus("Group state published.");
}

// ---- Named group creation ----------------------------------------------- //

$("newGroupBtn").onclick = () => {
  // Populate member checkboxes
  const box = $("memberCheckboxes");
  box.replaceChildren();
  for (const d of directory) {
    if (d.device_tag === me.device_tag) continue;
    const lbl = document.createElement("label");
    const chk = document.createElement("input");
    chk.type = "checkbox"; chk.value = d.device_tag;
    lbl.appendChild(chk);
    lbl.appendChild(document.createTextNode(" " + (d.username || d.device_tag.slice(0, 14) + "…")));
    box.appendChild(lbl);
  }
  $("groupNameInput").value = "";
  $("newGroupModal").classList.add("open");
};

$("cancelGroupBtn").onclick = () => $("newGroupModal").classList.remove("open");

$("createGroupBtn").onclick = async () => {
  const name = $("groupNameInput").value.trim();
  if (!name) { setStatus("Group name required."); return; }
  const checked = [...$("memberCheckboxes").querySelectorAll("input:checked")].map(c => c.value);
  const member_tags = [...checked, me.device_tag];
  try {
    setStatus("Creating group…");
    const r = await fetch("/api/groups/create", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, member_tags}),
    });
    const g = await r.json();
    if (!r.ok) throw new Error(g.error);
    groups.push(g);

    // Initialize group key for the new group
    const members = directory
      .filter(d => member_tags.includes(d.device_tag) && d.encryption_public_key)
      .map(d => ({device_tag: d.device_tag, encryption_public_key: d.encryption_public_key}));
    const state = await agent("/v1/group/create-state", {
      members, own_tag: me.device_tag, epoch: 1, group_id: g.group_id,
    });
    // Publish group key state via MLS events (reusing existing infra)
    // We send it to all members via the WebSocket push when they reconnect
    // For now, store locally — full MLS-per-group epoch tracking can be added later
    setStatus(`Group '${name}' created.`);
    $("newGroupModal").classList.remove("open");
    renderSidebar();
    openChannel({type: "group", id: g.group_id, name: "#" + g.name});
  } catch (e) {
    setStatus("Create group failed: " + e.message);
  }
};

// ---- Send message ------------------------------------------------------- //

async function sendMessage() {
  const text = $("textInput").value.trim();
  if (!text || !activeChannel) return;
  $("textInput").value = "";
  const plaintext = b64(new TextEncoder().encode(text));
  const messageId = crypto.randomUUID();
  try {
    if (activeChannel.type === "general") {
      const enc = await agent("/v1/group/encrypt", {plaintext, message_id: messageId, group_id: "general"});
      await fetch("/api/general", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({envelope: enc.envelope}),
      });
    } else if (activeChannel.type === "group") {
      const enc = await agent("/v1/group/encrypt", {plaintext, message_id: messageId, group_id: activeChannel.id});
      await fetch(`/api/groups/${activeChannel.id}/message`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({envelope: enc.envelope}),
      });
    } else if (activeChannel.type === "dm") {
      const target = directory.find(d => d.device_tag === activeChannel.id);
      if (!target) throw new Error("recipient not in directory");
      const enc = await agent("/v1/direct/encrypt", {
        recipient_public_key: target.encryption_public_key,
        plaintext, message_id: messageId,
      });
      await fetch("/api/private", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({recipient_tag: activeChannel.id, envelope: enc.envelope}),
      });
      // Show own sent message locally
      pushMessage(activeChannel, {
        _mid: messageId, sender: me.device_tag, senderLabel: "you", text,
      });
    }
  } catch (e) {
    setStatus("Send failed: " + e.message);
  }
}

// ---- File attach / download --------------------------------------------- //

$("attachBtn").onclick = () => $("fileInput").click();

$("fileInput").onchange = async () => {
  const file = $("fileInput").files[0];
  if (!file || !activeChannel) return;
  $("fileInput").value = "";
  if (!activeChannel) return;
  try {
    setStatus(`Encrypting ${file.name}…`);
    const rawBytes = new Uint8Array(await file.arrayBuffer());
    const groupId = activeChannel.type === "general" ? "general"
      : activeChannel.type === "group" ? activeChannel.id : null;

    let fileEnvelope, encryptedBytes;
    if (groupId) {
      // Group: encrypt with group key
      const enc = await agent("/v1/file/encrypt", {plaintext: b64(rawBytes), group_id: groupId});
      fileEnvelope = enc.envelope;
      // Convert ciphertext back to bytes for upload
      encryptedBytes = unb64(enc.envelope.ciphertext);
    } else {
      // DM: encrypt with recipient's direct key
      const target = directory.find(d => d.device_tag === activeChannel.id);
      if (!target) throw new Error("recipient not found");
      // For DMs, wrap in a direct envelope
      const enc = await agent("/v1/direct/encrypt", {
        recipient_public_key: target.encryption_public_key,
        plaintext: b64(rawBytes),
        message_id: crypto.randomUUID(),
      });
      fileEnvelope = enc.envelope;
      encryptedBytes = unb64(enc.envelope.ciphertext);
    }

    setStatus(`Uploading ${file.name}…`);
    const formData = new FormData();
    const encBlob = new Blob([encryptedBytes], {type: "application/octet-stream"});
    formData.append("file", encBlob, file.name + ".enc");
    formData.append("metadata", JSON.stringify({
      original_filename: file.name,
      size: file.size,
      file_envelope_alg: fileEnvelope.alg || fileEnvelope.kind,
    }));
    const uploadResp = await fetch("/api/files/upload", {method: "POST", body: formData});
    const uploaded = await uploadResp.json();
    if (!uploadResp.ok) throw new Error(uploaded.error);

    // Send file reference as a chat message
    const msgEnvelope = {
      type: "file",
      file_key: uploaded.file_key,
      filename: file.name,
      size: file.size,
      file_envelope: fileEnvelope, // contains nonce+ciphertext metadata for decryption
    };
    const messageId = crypto.randomUUID();
    if (activeChannel.type === "general") {
      // Wrap the file reference in a group envelope so the server validates it
      const enc = await agent("/v1/group/encrypt", {
        plaintext: b64(new TextEncoder().encode(JSON.stringify(msgEnvelope))),
        message_id: messageId, group_id: "general",
      });
      // Attach type=file hint at top level for quick detection without decrypt
      enc.envelope.type = "file";
      enc.envelope._file_ref = {file_key: uploaded.file_key, filename: file.name, size: file.size};
      await fetch("/api/general", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({envelope: enc.envelope}),
      });
    } else if (activeChannel.type === "group") {
      const enc = await agent("/v1/group/encrypt", {
        plaintext: b64(new TextEncoder().encode(JSON.stringify(msgEnvelope))),
        message_id: messageId, group_id: activeChannel.id,
      });
      enc.envelope.type = "file";
      enc.envelope._file_ref = {file_key: uploaded.file_key, filename: file.name, size: file.size};
      await fetch(`/api/groups/${activeChannel.id}/message`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({envelope: enc.envelope}),
      });
    } else if (activeChannel.type === "dm") {
      // For DM file, send the direct envelope reference as the message
      await fetch("/api/private", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          recipient_tag: activeChannel.id,
          envelope: {
            ...fileEnvelope,
            alg: fileEnvelope.alg || "x25519-chacha20poly1305-v1",
            type: "file",
            _file_ref: {file_key: uploaded.file_key, filename: file.name, size: file.size},
          },
        }),
      });
      pushMessage(activeChannel, {
        _mid: messageId, sender: me.device_tag, senderLabel: "you",
        isFile: true, fileKey: uploaded.file_key, filename: file.name, size: file.size, fileEnvelope,
      });
    }
    setStatus("File sent.");
  } catch (e) {
    setStatus("File upload failed: " + e.message);
  }
};

async function downloadFile(fileKey, filename, fileEnvelope) {
  try {
    setStatus(`Downloading ${filename}…`);
    const r = await fetch(`/api/files/${fileKey}`);
    if (!r.ok) throw new Error("download failed");
    const encBytes = new Uint8Array(await r.arrayBuffer());
    // Reconstruct the envelope ciphertext from the downloaded bytes
    const envelope = {...fileEnvelope, ciphertext: b64(encBytes)};
    let plainBytes;
    if (envelope.alg === "chacha20poly1305-group-file-v1") {
      const dec = await agent("/v1/file/decrypt", {envelope});
      plainBytes = unb64(dec.plaintext);
    } else if (envelope.alg === "x25519-chacha20poly1305-v1") {
      // DM file
      const dec = await agent("/v1/direct/decrypt", {envelope: {kind: "direct", payload: envelope}});
      plainBytes = unb64(dec.plaintext);
    } else {
      throw new Error("unknown file envelope algorithm");
    }
    const blob = new Blob([plainBytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    setStatus("Downloaded " + filename);
  } catch (e) {
    setStatus("Download failed: " + e.message);
  }
}

// ---- WebSocket ---------------------------------------------------------- //

function connectSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/ws`);

  socket.onmessage = async (event) => {
    const packet = JSON.parse(event.data);
    try {
      if (packet.kind === "general") {
        const m = packet.message;
        let text, isFile = false, fileKey, filename, size, fileEnvelope;
        const env = m.envelope;
        if (env._file_ref) {
          isFile = true;
          fileKey = env._file_ref.file_key;
          filename = env._file_ref.filename;
          size = env._file_ref.size;
          // Decrypt to get full file envelope
          try {
            const patchedEnv = {...env, kind: "group", group_id: "general"};
            const dec = await agent("/v1/group/decrypt", {envelope: patchedEnv});
            fileEnvelope = JSON.parse(new TextDecoder().decode(unb64(dec.plaintext))).file_envelope;
          } catch (_) {}
        } else {
          const patchedEnv = {...env, kind: "group", group_id: "general"};
          const dec = await agent("/v1/group/decrypt", {envelope: patchedEnv});
          text = new TextDecoder().decode(unb64(dec.plaintext));
        }
        pushMessage({type: "general", id: "general"}, {
          _mid: m.message_id, sender: m.sender_tag, senderLabel: senderLabel(m.sender_tag),
          text, isFile, fileKey, filename, size, fileEnvelope,
        });

      } else if (packet.kind === "private") {
        const m = packet.message;
        const sender = m.sender_tag;
        let text, isFile = false, fileKey, filename, size, fileEnvelope;
        const env = m.envelope;
        if (env._file_ref) {
          isFile = true;
          fileKey = env._file_ref.file_key;
          filename = env._file_ref.filename;
          size = env._file_ref.size;
          fileEnvelope = env;
        } else {
          const dec = await agent("/v1/direct/decrypt", {envelope: env});
          text = new TextDecoder().decode(unb64(dec.plaintext));
        }
        // Determine which DM channel to put this in
        const ch = {type: "dm", id: sender, name: senderLabel(sender)};
        if (!messageHistory["dm:" + sender]) messageHistory["dm:" + sender] = [];
        pushMessage(ch, {
          _mid: m.message_id, sender, senderLabel: senderLabel(sender),
          text, isFile, fileKey, filename, size, fileEnvelope,
        });
        renderSidebar();
        socket.send(JSON.stringify({kind: "ack", message_id: m.message_id}));

      } else if (packet.kind === "group") {
        const m = packet.message;
        const gid = packet.group_id;
        let text, isFile = false, fileKey, filename, size, fileEnvelope;
        const env = m.envelope;
        if (env._file_ref) {
          isFile = true;
          fileKey = env._file_ref.file_key;
          filename = env._file_ref.filename;
          size = env._file_ref.size;
          try {
            const dec = await agent("/v1/group/decrypt", {envelope: {...env, kind: "group", group_id: gid}});
            fileEnvelope = JSON.parse(new TextDecoder().decode(unb64(dec.plaintext))).file_envelope;
          } catch (_) {}
        } else {
          const dec = await agent("/v1/group/decrypt", {envelope: {...env, kind: "group", group_id: gid}});
          text = new TextDecoder().decode(unb64(dec.plaintext));
        }
        const g = groups.find(x => x.group_id === gid);
        const ch = {type: "group", id: gid, name: g ? "#" + g.name : gid};
        pushMessage(ch, {
          _mid: m.message_id, sender: m.sender_tag, senderLabel: senderLabel(m.sender_tag),
          text, isFile, fileKey, filename, size, fileEnvelope,
        });

      } else if (packet.kind === "mls") {
        const ev = packet.event;
        if (ev.payload && ev.payload.kind === "tree-group-state-v1") {
          try {
            await agent("/v1/group/install-state", {state: ev.payload, own_tag: me.device_tag});
            setStatus(`Group epoch ${ev.payload.epoch} installed.`);
          } catch (_) {}
        }
      }
    } catch (e) {
      setStatus("Decrypt error: " + e.message);
    }
  };

  socket.onclose = () => setTimeout(connectSocket, 1500);
}

// ---- Profile ------------------------------------------------------------ //

$("usernameInput").onkeydown = async (e) => {
  if (e.key !== "Enter") return;
  const r = await fetch("/api/me/username", {
    method: "PATCH", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: $("usernameInput").value.trim()}),
  });
  if (r.ok) {
    me = await r.json();
    $("myTag").textContent = (me.username || "") + " " + me.device_tag.slice(0, 12) + "…";
    await loadDirectory();
    setStatus("Username saved.");
  }
};

// ---- Event wiring ------------------------------------------------------- //

$("sendBtn").onclick = () => sendMessage().catch(e => setStatus(e.message));
$("textInput").onkeydown = (e) => { if (e.key === "Enter") sendMessage().catch(e2 => setStatus(e2.message)); };
$("loginButton").onclick = () => authenticate().catch(e => $("loginStatus").textContent = e.message);

// ---- Helpers ------------------------------------------------------------ //

function setStatus(msg) { $("status").textContent = msg; }
function escHtml(s) { return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

// Auto-refresh directory every 15s
setInterval(async () => {
  if (!me) return;
  await loadDirectory().catch(() => {});
  await loadGroups().catch(() => {});
  renderSidebar();
}, 15000);

$("login").style.display = "block";
