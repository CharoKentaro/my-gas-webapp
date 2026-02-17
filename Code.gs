/**
 * TRC Unified Foundation Core
 * Version: 25.1 (Zenith / Quota Fix) - Embedded for X-Silence
 * 
 * 修正点: 
 * 1. testConnection: 最新モデルが混雑していても安定版で認証を通すように変更
 * 2. callGeminiEngine: 429(RateLimit)を即時エラーにせず、リトライ/他モデルへ迂回するよう緩和
 */

// =====================================================================
// [Foundation] 0. 型定義 & ユーティリティ
// =====================================================================

const DEFAULT_CONFIG_SHEET_ID = "YOUR_CONFIG_SPREADSHEET_ID_HERE"; 
const CACHE_DURATION_MS = 6 * 60 * 60 * 1000;
const MAX_RETRIES = 2; 
const RETRY_BASE_DELAY_MS = 1500; 
const DATA_SIZE_LIMIT_BYTES = 100000; 
const CHUNK_SIZE = 8500; 
const LOG_RETENTION_DAYS = 90;
const FALLBACK_MODELS = ["gemini-3-pro-preview", "gemini-2.5-flash", "gemini-2.5-pro"];
const ALLOWED_MODEL_PREFIXES = ["gemini-", "models/gemini-", "learnlm-", "corallm-"];

const Utils_ = {
  formatDate: function(date, format = 'YYYY/MM/DD HH:mm') {
    const d = date instanceof Date ? date : new Date(date);
    const pad = n => String(n).padStart(2, '0');
    return format.replace('YYYY', d.getFullYear()).replace('MM', pad(d.getMonth()+1)).replace('DD', pad(d.getDate())).replace('HH', pad(d.getHours())).replace('mm', pad(d.getMinutes()));
  },
  generateId: function(prefix = '') { return prefix + Utilities.getUuid().replace(/-/g, '').substring(0, 12); },
  deepMerge: function(target, source) {
    const output = Object.assign({}, target);
    if (typeof target === 'object' && typeof source === 'object') {
      Object.keys(source).forEach(key => {
        if (typeof source[key] === 'object' && !Array.isArray(source[key])) output[key] = this.deepMerge(target[key] || {}, source[key]);
        else output[key] = source[key];
      });
    }
    return output;
  }
};

const DataSchema_ = {
  validate: function(data, schema) {
    if (!schema) return { valid: true };
    const errors = [];
    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      if (rules.required && (value === undefined || value === null)) { errors.push(`Field '${field}' is required`); continue; }
      if (value !== undefined && value !== null) {
        if (rules.type === 'date' && !(value instanceof Date) && isNaN(new Date(value))) errors.push(`Field '${field}' must be a valid date`);
        else if (rules.type === 'array' && !Array.isArray(value)) errors.push(`Field '${field}' must be an array`);
        else if (rules.type !== 'array' && rules.type !== 'date' && typeof value !== rules.type) errors.push(`Field '${field}' must be ${rules.type}`);
      }
    }
    return { valid: errors.length === 0, errors };
  }
};

const CircuitBreaker_ = {
  getCache: function() { return CacheService.getScriptCache(); },
  isOpen: function(model) { return this.getCache().get(`CB_${model}`) === 'OPEN'; },
  recordFailure: function(model) { this.getCache().put(`CB_${model}`, 'OPEN', 60); console.warn(`Circuit Breaker OPEN: ${model}`); },
  recordSuccess: function(model) { this.getCache().remove(`CB_${model}`); }
};

// =====================================================================
// [Foundation] 1. セキュリティ (PBKDF2 + HMAC)
// =====================================================================
const Security_ = {
  getUserSecret: function(rotate = false) {
    try {
      const props = PropertiesService.getUserProperties();
      let secret = props.getProperty('USER_SECRET');
      if (!secret) {
        secret = 'v1:' + Utilities.getUuid();
        props.setProperties({ 'USER_SECRET': secret, 'SECRET_VERSION': '1', 'SECRET_CREATED_AT': new Date().toISOString() });
        return secret;
      }
      if (rotate) {
        const oldVersion = parseInt(props.getProperty('SECRET_VERSION') || '1');
        const newSecret = `v${oldVersion + 1}:` + Utilities.getUuid();
        const oldSecrets = JSON.parse(props.getProperty('OLD_SECRETS') || '[]');
        oldSecrets.unshift({ version: oldVersion, secret: secret, retiredAt: new Date().toISOString() });
        if (oldSecrets.length > 5) oldSecrets.pop();
        props.setProperties({ 'USER_SECRET': newSecret, 'SECRET_VERSION': (oldVersion+1).toString(), 'SECRET_CREATED_AT': new Date().toISOString(), 'OLD_SECRETS': JSON.stringify(oldSecrets) });
        return newSecret;
      }
      return secret;
    } catch (e) { throw new Error("SECURITY_INIT_FAILED"); }
  },
  encrypt: function(text) {
    if (!text) return "";
    try {
      const rawSecret = this.getUserSecret();
      const salt = Utilities.getUuid(); const iv = Utilities.getUuid();
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) { derivedKey = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i)); }
      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const textBytes = Utilities.newBlob(text).getBytes();
      const encryptedBytes = textBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      const cipherB64 = Utilities.base64Encode(encryptedBytes);
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const mac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      return dataToSign + ":" + mac;
    } catch (e) { throw new Error("ENCRYPTION_FAILED"); }
  },
  decrypt: function(encryptedStr) {
    if (!encryptedStr) return "";
    if (encryptedStr.split(":").length === 2) return this._decryptLegacy(encryptedStr);
    const currentSecret = this.getUserSecret();
    let res = this._decryptStrong(encryptedStr, currentSecret);
    if (res !== null) return res;
    try {
      const oldSecrets = JSON.parse(PropertiesService.getUserProperties().getProperty('OLD_SECRETS') || '[]');
      for (const entry of oldSecrets) { res = this._decryptStrong(encryptedStr, entry.secret); if (res !== null) return res; }
    } catch(e) {}
    return "";
  },
  _decryptStrong: function(encryptedStr, rawSecret) {
    try {
      const parts = encryptedStr.split(":");
      if (parts.length !== 4) return null;
      const [salt, iv, cipherB64, receivedMac] = parts;
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) { derivedKey = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i)); }
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const computedMac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      if (computedMac !== receivedMac) return null;
      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const encryptedBytes = Utilities.base64Decode(cipherB64);
      const decryptedBytes = encryptedBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      const result = Utilities.newBlob(decryptedBytes).getDataAsString();
      if (result && !/[\uFFFD]/.test(result)) return result;
      return null;
    } catch(e) { return null; }
  },
  _decryptLegacy: function(str) {
    try {
      const secret = this.getUserSecret();
      const parts = str.split(":");
      const salt = parts[0];
      const bytes = Utilities.base64Decode(parts[1]);
      const ks = Utilities.computeHmacSha256Signature(salt, secret);
      const dec = bytes.map((b,i) => b ^ ks[i % ks.length]);
      return Utilities.newBlob(dec).getDataAsString();
    } catch(e) { return ""; }
  }
};

// =====================================================================
// [Foundation] 2. データ管理 (Foundation Prefix)
// =====================================================================
function Foundation_saveChunkedData_(keyPrefix, dataStr) {
  const props = PropertiesService.getUserProperties();
  const metaKey = keyPrefix + '_META';
  const oldMeta = props.getProperty(metaKey);
  if (oldMeta) { try { const c = JSON.parse(oldMeta).chunks; for(let i=0; i<c; i++) props.deleteProperty(keyPrefix+'_'+i); } catch(e){} }
  const chunks = [];
  for(let i=0; i<dataStr.length; i+=CHUNK_SIZE) chunks.push(dataStr.substring(i, i+CHUNK_SIZE));
  const payload = {};
  payload[metaKey] = JSON.stringify({ chunks: chunks.length, timestamp: new Date().getTime() });
  chunks.forEach((chunk, index) => { payload[keyPrefix + '_' + index] = chunk; });
  props.setProperties(payload);
}

function Foundation_loadChunkedData_(keyPrefix) {
  const props = PropertiesService.getUserProperties();
  const legacyData = props.getProperty(keyPrefix);
  if (legacyData && !props.getProperty(keyPrefix+'_META')) return legacyData;
  const metaJson = props.getProperty(keyPrefix+'_META');
  if (!metaJson) return null;
  try {
    const meta = JSON.parse(metaJson);
    let fullData = "";
    for(let i=0; i<meta.chunks; i++) { const c = props.getProperty(keyPrefix+'_'+i); if(!c) return null; fullData += c; }
    return fullData;
  } catch(e) { return null; }
}

function Foundation_saveUserData(dataObj, schema = null) {
  try {
    if (!dataObj || typeof dataObj !== 'object') throw new Error("INVALID_DATA_TYPE");
    if (schema) {
      const v = DataSchema_.validate(dataObj, schema);
      if (!v.valid) throw new Error("SCHEMA_VALIDATION_FAILED: " + v.errors.join(", "));
    }
    let jsonStr = JSON.stringify(dataObj);
    if (Utilities.newBlob(jsonStr).getBytes().length > DATA_SIZE_LIMIT_BYTES) throw new Error("DATA_SIZE_LIMIT_EXCEEDED_100KB");
    const encrypted = Security_.encrypt(jsonStr);
    Foundation_saveChunkedData_('APP_DATA', encrypted);
    return { success: true };
  } catch (e) {
    logSystemError_("saveUserData", e);
    return { success: false, error: e.message };
  }
}

function Foundation_loadUserData() {
  try {
    const props = PropertiesService.getUserProperties();
    const encKey = props.getProperty('GEMINI_KEY');
    const apiKey = Security_.decrypt(encKey);
    const hasKey = !!(encKey && apiKey && apiKey.length > 20);
    const encData = Foundation_loadChunkedData_('APP_DATA');
    let data = null;
    if (encData) {
      const jsonStr = Security_.decrypt(encData);
      try { data = jsonStr ? JSON.parse(jsonStr) : {}; } catch(e) { data = {}; }
    }
    return { success: true, hasApiKey: hasKey, data: data || {} };
  } catch (e) {
    logSystemError_("loadUserData", e);
    return { success: false, error: e.message };
  }
}

function Foundation_saveApiKey(key) {
  try {
    const k = key ? key.trim() : "";
    if (k.length < 30) throw new Error("KEY_FORMAT_INVALID");
    PropertiesService.getUserProperties().setProperty('GEMINI_KEY', Security_.encrypt(k));
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function Foundation_deleteUserData(hard) {
  const props = PropertiesService.getUserProperties();
  if (!hard) {
    const backup = { data: Foundation_loadChunkedData_('APP_DATA'), key: props.getProperty('GEMINI_KEY'), deletedAt: new Date().toISOString() };
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    props.deleteAllProperties();
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    const restoreUntil = new Date(new Date().getTime() + 24*60*60*1000);
    return { success: true, mode: 'soft', restoreUntil: restoreUntil.toLocaleString('ja-JP') };
  }
  props.deleteAllProperties();
  return { success: true, mode: 'hard' };
}

function Foundation_restoreUserData() {
  try {
    const props = PropertiesService.getUserProperties();
    const backupJson = props.getProperty('DELETED_BACKUP');
    if (!backupJson) return { success: false, error: "NO_BACKUP_FOUND" };
    const backup = JSON.parse(backupJson);
    if ((new Date() - new Date(backup.deletedAt)) > 86400000) return { success: false, error: "BACKUP_EXPIRED" };
    if (backup.data) Foundation_saveChunkedData_('APP_DATA', Security_.encrypt(backup.data));
    if (backup.key) props.setProperty('GEMINI_KEY', backup.key);
    props.deleteProperty('DELETED_BACKUP');
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function Foundation_clearUserCache() {
  const props = PropertiesService.getUserProperties();
  const meta = props.getProperty('APP_DATA_META');
  if(meta) { try { const c = JSON.parse(meta).chunks; for(let i=0; i<c; i++) props.deleteProperty('APP_DATA_'+i); props.deleteProperty('APP_DATA_META'); } catch(e){} }
  props.deleteProperty('APP_DATA');
  return { success: true };
}

// =====================================================================
// [Foundation] 3. ログ & 設定 & AIエンジン (修正版)
// =====================================================================
function logSystemError_(funcName, errorObj) {
  const email = Session.getActiveUser().getEmail() || "Anonymous";
  let userHash = email;
  if (email !== "Anonymous") userHash = "u_" + Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, email).map(b => (b < 0 ? b + 256 : b).toString(16).padStart(2, '0')).join('').substring(0, 16);
  const formatted = (errorObj instanceof Error) ? {name:errorObj.name, message:errorObj.message, stack:errorObj.stack} : {message:String(errorObj)};
  console.error({ function: funcName, user: userHash, error: formatted.message, details: formatted });
  try {
    const sheetId = PropertiesService.getScriptProperties().getProperty('CONFIG_SHEET_ID') || DEFAULT_CONFIG_SHEET_ID;
    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName("Error_Logs");
    if (!sheet) { sheet = ss.insertSheet("Error_Logs"); sheet.appendRow(["Timestamp", "UserHash", "Function", "ErrorMessage", "Details", "RetentionUntil"]); sheet.setFrozenRows(1); }
    const retentionDate = new Date(); retentionDate.setDate(retentionDate.getDate() + LOG_RETENTION_DAYS);
    sheet.appendRow([new Date(), userHash, funcName, formatted.message, JSON.stringify(formatted), retentionDate]);
  } catch (e) { console.warn("Log Failed:", e); }
}

function adminUpdateConfig() {
  try {
    const sheetId = PropertiesService.getScriptProperties().getProperty('CONFIG_SHEET_ID') || DEFAULT_CONFIG_SHEET_ID;
    const ss = SpreadsheetApp.openById(sheetId);
    const values = ss.getSheets()[0].getDataRange().getValues();
    const models = values.flat().map(v => String(v).trim()).filter(v => ALLOWED_MODEL_PREFIXES.some(p => v.toLowerCase().startsWith(p)));
    const unique = [...new Set(models)];
    if (unique.length === 0) return FALLBACK_MODELS;
    PropertiesService.getScriptProperties().setProperties({ 'GLOBAL_MODELS': JSON.stringify(unique), 'LAST_UPDATE_TIME': new Date().getTime().toString() });
    return unique;
  } catch (e) { return FALLBACK_MODELS; }
}

function getModelCandidates() {
  try {
    const props = PropertiesService.getScriptProperties();
    const json = props.getProperty("GLOBAL_MODELS");
    const lastUpdate = parseInt(props.getProperty("LAST_UPDATE_TIME") || "0");
    if (json && (new Date().getTime() - lastUpdate < CACHE_DURATION_MS)) return JSON.parse(json);
    return adminUpdateConfig();
  } catch (e) { return FALLBACK_MODELS; }
}

/**
 * AIエンジン呼び出し (修正版: 429緩和ロジック)
 * 429エラーが出ても即死せず、リトライおよび他モデルへのフォールバックを優先する
 */
function callGeminiEngine(prompt, systemInstruction = "") {
  try {
    const encKey = PropertiesService.getUserProperties().getProperty('GEMINI_KEY');
    if (!encKey) throw new Error("NO_API_KEY");
    const apiKey = Security_.decrypt(encKey);
    if (!apiKey) throw new Error("INVALID_KEY_STORED");

    const models = getModelCandidates();
    let lastError = "";
    
    // 全モデル試行後に初めてQuota判定を行うためのフラグ
    let allModelsQuotaError = true;

    for (const model of models) {
      if (CircuitBreaker_.isOpen(model)) continue;
      
      let thisModelQuota = false; // このモデル単体のQuota/RateLimitフラグ

      for (let retry = 0; retry <= MAX_RETRIES; retry++) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
        const payload = { contents: [{ parts: [{ text: prompt }] }] };
        if (systemInstruction) payload.systemInstruction = { parts: [{ text: systemInstruction }] };
        const options = { method: 'post', contentType: 'application/json', headers: { 'x-goog-api-key': apiKey }, payload: JSON.stringify(payload), muteHttpExceptions: true, timeout: 30 };

        try {
          const response = UrlFetchApp.fetch(url, options);
          const code = response.getResponseCode();
          
          // 成功時
          if (code === 200) {
            const json = JSON.parse(response.getContentText());
            const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) { 
              CircuitBreaker_.recordSuccess(model); 
              return { success: true, text: text, model: model }; 
            }
          }
          
          const body = response.getContentText();
          let errorMsg = body; try { errorMsg = JSON.parse(body).error.message; } catch(_){}
          
          // APIキー無効は即死
          if (code === 400 && errorMsg.includes("API_KEY_INVALID")) throw new Error("INVALID_KEY_DETECTED");

          // リトライ可能なエラー (500系, 429, 一部の403)
          if (code >= 500 || code === 429 || (code === 403 && errorMsg.includes("Quota"))) {
            if (code === 429 || code === 403) thisModelQuota = true;

            if (retry < MAX_RETRIES) {
              // 待機してリトライ
              Utilities.sleep((RETRY_BASE_DELAY_MS * Math.pow(2, retry)) + (Math.random() * 500)); 
              continue; 
            } else {
              // リトライ尽きたらサーキットオープン
              CircuitBreaker_.recordFailure(model);
            }
          }
          
          lastError += `[${model}:${code}] `; 
          break; // 次のモデルへ

        } catch (innerE) {
          if (innerE.message === "INVALID_KEY_DETECTED") throw innerE;
          lastError += `[${model}:Err] `; 
          break; // 次のモデルへ
        }
      }
      
      // このモデルがQuota以外で失敗していたら、全モデルQuotaエラーではない
      if (!thisModelQuota) allModelsQuotaError = false;
    }

    // 全てのモデルを試した後
    // もし全モデルがQuota/RateLimitで失敗していた場合のみ、ユーザーに制限通知を出す
    if (allModelsQuotaError && lastError.length > 0) {
       return { success: false, error: "QUOTA_EXCEEDED_STRICT" };
    }

    throw new Error("ALL_MODELS_FAILED: " + lastError);

  } catch (e) { return { success: false, error: e.message }; }
}

/**
 * 接続テスト (修正版: 複数モデル試行)
 * 1つでも繋がればOKとする
 */
function Foundation_testConnection(apiKey) {
  if (!apiKey || apiKey.trim().length < 30) return { success: false, error: "KEY_FORMAT_INVALID" };
  const cleanKey = apiKey.trim();
  
  // テスト用候補 (設定 + 安定版Flash)
  const candidates = getModelCandidates();
  candidates.push("gemini-1.5-flash");
  const models = [...new Set(candidates)];
  
  let lastError = "CONNECTION_FAILED";

  for (const model of models) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
      const options = { method: 'post', contentType: 'application/json', headers: { 'x-goog-api-key': cleanKey }, payload: JSON.stringify({ contents: [{ parts: [{ text: "Hi" }] }] }), muteHttpExceptions: true };
      
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      
      if (code === 200) return { success: true };
      
      const body = response.getContentText();
      // キー無効は即終了
      if (code === 400 && body.includes("API_KEY_INVALID")) return { success: false, error: "INVALID_KEY_DETECTED" };
      
      // 429等は次のモデルへ
      if (code === 429) lastError = "QUOTA_OR_RATE_LIMIT";
      else lastError = `HTTP_${code}`;
      
    } catch (e) { lastError = e.message; }
  }
  
  return { success: false, error: lastError };
}

function runSystemSelfCheck() {
  const report = { encryption: false, data: false, config: false };
  try {
    const testStr = "TRC_" + Utilities.getUuid();
    if (Security_.decrypt(Security_.encrypt(testStr)) === testStr) report.encryption = true;
    Foundation_saveChunkedData_("SELF_TEST", "A".repeat(15000));
    if (Foundation_loadChunkedData_("SELF_TEST").length === 15000) report.data = true;
    PropertiesService.getUserProperties().deleteProperty("SELF_TEST_META");
    if (getModelCandidates().length > 0) report.config = true;
    return { success: true, report: report };
  } catch(e) { return { success: false, error: e.message, report: report }; }
}

// =====================================================================
// [Adapter] 既存アプリとの接合部 (X-Silence Logic)
// =====================================================================

// 3. Webアプリのエントリーポイント (既存維持)
function doGet() {
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('X-Silence (TRC Zenith)')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// 4. データ永続化・認証 (Simple Adapter)
function loadUserData() {
  return Foundation_loadUserData();
}

function saveUserData(dataObj) {
  return Foundation_saveUserData(dataObj);
}

function saveApiKey(key) {
  return Foundation_saveApiKey(key);
}

function clearAllData() {
  return Foundation_deleteUserData(true);
}

function restoreUserData() { return Foundation_restoreUserData(); }
function clearUserCache() { return Foundation_clearUserCache(); }

// 5. AIロジック (X-Silence)

function testApiKey(apiKey) {
  const res = Foundation_testConnection(apiKey);
  if (res.success) {
    return { success: true, message: "接続成功 (Gemini AI)" };
  } else {
    return { success: false, message: res.error };
  }
}

// 機能B: X-Silence 投稿診断
function analyzePost(apiKeyArg, text) {
  try {
    const prompt = `
      あなたは詐欺・スパム検知AIです。以下の投稿を分析してください。
      テキスト: "${text}"
      出力JSON: { "riskLevel": 0-100, "verdict": "安全/注意/危険", "analysis": "理由" }
    `;
    
    const result = callGeminiEngine(prompt);
    if (!result.success) throw new Error(result.error);

    const jsonStr = extractJson_(result.text);
    let data;
    try { data = JSON.parse(jsonStr); }
    catch (e) { data = { riskLevel: 0, verdict: "不明", analysis: "解析失敗: " + e.message }; }
    
    return { success: true, data: data, model: formatModelName_(result.model) };
  } catch (e) { return { success: false, error: e.message }; }
}

// 機能C: X-Silence 検索コマンド
function generateQuietSearch(apiKeyArg, params) {
  try {
    const actualParams = params || apiKeyArg; 
    const noLinks = actualParams.noLinks === true;
    const includeReplies = actualParams.includeReplies === true;

    const prompt = `
      X(Twitter)検索コマンドを作成してください。
      トピック: "${actualParams.topic}"
      最低いいね: ${actualParams.minFavs}
      リンク除外: ${noLinks ? "はい" : "いいえ"}
      リプライ: ${includeReplies ? "含める" : "除外する"}
      出力JSON: { "query": "コマンド", "reason": "説明" }
    `;
    
    const result = callGeminiEngine(prompt);
    if (!result.success) throw new Error(result.error);

    const jsonStr = extractJson_(result.text);
    let data;
    try { data = JSON.parse(jsonStr); }
    catch (e) { data = { query: actualParams.topic, reason: "生成失敗" }; }

    return { success: true, ...data, usedModel: formatModelName_(result.model) };
  } catch (e) { return { success: false, error: e.message }; }
}

// 6. ユーティリティ
function extractJson_(text) {
  if (!text) return "{}";
  let clean = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const first = clean.indexOf('{'), last = clean.lastIndexOf('}');
  if (first !== -1 && last > first) return clean.substring(first, last + 1);
  return clean;
}

function formatModelName_(raw) {
  if (!raw) return "AI";
  if (raw.includes("gemini-3")) return "✨ Gemini 3.0 Pro";
  if (raw.includes("2.5-flash")) return "⚡ Gemini 2.5 Flash";
  return "🤖 " + raw.replace("models/", "");
}
