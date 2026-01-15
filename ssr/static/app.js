const state = {
  ticket: null,
  user: null,
  ws: null,
  currentPath: window.location.pathname,
  isRegistering: false,
};

// ...

// ...

// --- OPFS Storage ---
async function saveTicket(user, ticket) {
  try {
    const root = await navigator.storage.getDirectory();
    // Check if user dir exists or just use flat file for now?
    // Let's use simplified flat file 'ticket' and 'user'

    const ticketHandle = await root.getFileHandle('ticket', { create: true });
    const ticketWritable = await ticketHandle.createWritable();
    await ticketWritable.write(ticket);
    await ticketWritable.close();

    const userHandle = await root.getFileHandle('user', { create: true });
    const userWritable = await userHandle.createWritable();
    await userWritable.write(user);
    await userWritable.close();

    console.log("Ticket saved to OPFS");
  } catch (e) {
    console.error("Failed to save ticket:", e);
  }
}

async function loadTicket() {
  try {
    const root = await navigator.storage.getDirectory();

    const ticketHandle = await root.getFileHandle('ticket'); // Will throw if missing
    const ticketFile = await ticketHandle.getFile();
    const ticket = await ticketFile.text();

    const userHandle = await root.getFileHandle('user');
    const userFile = await userHandle.getFile();
    const user = await userFile.text();

    if (ticket && user) {
      state.ticket = ticket;
      state.user = user;
      return { ticket, user };
    }
  } catch (e) {
    // Not found is fine
  }
  return null;
}

// --- WebSocket ---
function connect() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${window.location.host}/ws`;

  console.log(`Connecting to ${url}...`);
  state.ws = new WebSocket(url);

  state.ws.onopen = async () => {
    console.log("Connected");

    // Explicitly handle Register page
    if (state.currentPath === "/register") {
      console.log("On /register, rendering registration form");
      renderRegister();
      return;
    }

    const creds = await loadTicket();
    if (creds) {
      console.log("Found ticket, authenticating as", creds.user);
      // Protocol: auth user=<user> ticket=<ticket>
      send(`auth user=${creds.user} ticket=${creds.ticket}`);
    } else {
      console.log("No ticket, requesting nav to trigger login...");
      // Protocol: nav path=<path>
      send(`nav path=${state.currentPath}`);
    }
  };

  state.ws.onmessage = (event) => {
    try {
      const msg = event.data;
      handleMessage(msg);
    } catch (e) {
      console.error("Invalid message:", event.data, e);
    }
  };

  state.ws.onclose = () => {
    console.log("Disconnected. Reconnecting in 1s...");
    setTimeout(connect, 1000);
  };
}

function send(msg) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(msg); // Send raw text
  } else {
    console.warn("WebSocket not open, message dropped:", msg);
  }
}

function handleMessage(msg) {
  console.log("Received:", msg);

  // Parse: verb param1=val1 param2=val2 ...
  const parts = msg.split(' ');
  if (parts.length === 0) return;

  const verb = parts[0];
  const params = {};
  for (let i = 1; i < parts.length; i++) {
    const kv = parts[i].split('=');
    if (kv.length === 2) {
      params[kv[0]] = kv[1];
    }
  }

  switch (verb) {
    case "render":
      // Protocol: render path=<path> html=<base64>
      if (params.html) {
        const path = params.path;

        // Decode Base64
        const htmlContent = atob(params.html);

        // Update URL if changed (pushState)
        if (path && path !== state.currentPath) {
          history.pushState({ path: path }, "", path);
          state.currentPath = path;
        }

        // Naive replacement
        const parser = new DOMParser();
        const newDoc = parser.parseFromString(htmlContent, "text/html");

        // Update Body
        document.body.replaceWith(newDoc.body);

        // Re-bind events (since body replaced)
        bindEvents();

        // Ideally update Title
        document.title = newDoc.title;
      }
      break;

    case "challenge":
      // Protocol: challenge <base64_challenge>
      if (params.challenge) {
        handleRegisterChallenge(params.challenge);
      }
      break;

    case "ticket":
      // Protocol: ticket ticket=<ticket>
      if (params.ticket) {
        saveTicket(state.user, params.ticket).then(() => {
          // Determine next step. If we just got a ticket, we should Auth.
          send(`auth user=${state.user} ticket=${params.ticket}`);
        });
      }
      break;

    case "login_required":
      renderLogin(params.error);
      break;

    case "error":
      console.error("Server Error:", params.msg);
      break;

    default:
      console.warn("Unknown message:", verb);
  }
}

async function handleRegisterChallenge(challengeBase64) {
  try {
    const challenge = base64ToArrayBuffer(challengeBase64);
    const userId = new TextEncoder().encode(state.user); // Simple user ID for now

    const publicKey = {
      challenge: challenge,
      rp: { name: "Ten System", id: window.location.hostname },
      user: {
        id: userId,
        name: state.user,
        displayName: state.user
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
      timeout: 60000,
      attestation: "none"
    };

    console.log("Creating credential...", publicKey);
    const cred = await navigator.credentials.create({ publicKey });

    // Convert to JSON for Server
    const credentialJSON = {
      id: cred.id,
      rawId: bufferToBase64URL(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufferToBase64URL(cred.response.attestationObject),
        clientDataJSON: bufferToBase64URL(cred.response.clientDataJSON)
      }
    };

    const responseBase64 = btoa(JSON.stringify(credentialJSON));
    send(`register_finish response=${responseBase64}`);

  } catch (e) {
    console.error("WebAuthn Create Failed:", e);
    alert("Registration failed: " + e.message);
    state.isRegistering = false;

    // Re-enable button
    const btn = document.querySelector('#register-form button');
    if (btn) {
      btn.disabled = false;
      btn.innerText = "Generate Key & Register";
    }
  }
}

// --- Helpers ---
function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64URL(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// --- UI ---
function renderLogin(error) {
  const html = `
        <div class="login-container" style="display: flex; justify-content: center; align-items: center; height: 100vh;">
            <div class="login-box" style="border: 1px solid var(--border); padding: 2rem; width: 300px;">
                <h2>Login</h2>
                ${error ? `<p style="color: red;">${error}</p>` : ''}
                <form id="login-form">
                    <label style="display: block; margin-bottom: 0.5rem;">Username</label>
                    <input type="text" id="username" name="username" autofocus style="width: 100%; margin-bottom: 1rem; padding: 0.5rem; background: var(--bg); color: var(--fg); border: 1px solid var(--border);">
                    <button type="submit" style="width: 100%; padding: 0.5rem; cursor: pointer; background: var(--fg); color: var(--bg); border: none;">Login</button>
                </form>
                <div style="margin-top: 1rem; text-align: center;">
                    <a href="#" id="register-link" style="color: var(--fg);">Generate Key (First Time)</a>
                </div>
            </div>
        </div>
    `;
  // We can replace just the body content
  document.body.innerHTML = html;

  document.getElementById('login-form').onsubmit = (e) => {
    e.preventDefault();
    const user = document.getElementById('username').value;
    if (user) {
      state.user = user; // Temporary store
      // Protocol: login user=<user>
      send(`login user=${user}`);
    }
  };

  document.getElementById('register-link').onclick = (e) => {
    e.preventDefault();
    renderRegister();
  };
}

function renderRegister() {
  // Placeholder for Phase 2 TOFU Registration
  const html = `
        <div class="login-container" style="display: flex; justify-content: center; align-items: center; height: 100vh;">
            <div class="login-box" style="border: 1px solid var(--border); padding: 2rem; width: 300px;">
                <h2>Register (Admin)</h2>
                <p>Trust-On-First-Use: The first user to register becomes Admin.</p>
                <form id="register-form">
                    <label style="display: block; margin-bottom: 0.5rem;">Username (admin)</label>
                    <input type="text" id="reg-username" name="username" value="admin" readonly style="width: 100%; margin-bottom: 1rem; padding: 0.5rem; background: var(--bg); color: var(--fg); border: 1px solid var(--border);">
                    <button type="submit" style="width: 100%; padding: 0.5rem; cursor: pointer; background: var(--fg); color: var(--bg); border: none;">Generate Key & Register</button>
                </form>
                <div style="margin-top: 1rem; text-align: center;">
                    <a href="#" onclick="location.reload(); return false;" style="color: var(--fg);">Back to Login</a>
                </div>
            </div>
        </div>
    `;
  document.body.innerHTML = html;

  document.getElementById('register-form').onsubmit = (e) => {
    e.preventDefault();
    if (state.isRegistering) return;
    state.isRegistering = true;

    const btn = e.target.querySelector('button');
    btn.disabled = true;
    btn.innerText = "Generating...";

    const user = document.getElementById('reg-username').value;
    state.user = user;
    send(`register user=${user}`);
  };
}

function bindEvents() {
  // Intercept clicks
  document.body.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link) {
      const href = link.getAttribute('href');
      if (href && href.startsWith('/')) {
        e.preventDefault();
        console.log("Navigating to", href);
        // Protocol: nav path=<path>
        send(`nav path=${href}`);
      }
    }
  });
}

// System Boot
bindEvents();
connect();

// History Popstate
window.onpopstate = (e) => {
  const path = window.location.pathname;
  state.currentPath = path;
  send({ type: "nav", path: path });
};
