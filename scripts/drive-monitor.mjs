import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, createSign } from 'node:crypto';

const statePath = path.resolve('state/drive-sync.json');
const summaryPath = process.env.GITHUB_STEP_SUMMARY;
const required = ['GOOGLE_SERVICE_ACCOUNT_JSON', 'DRIVE_ROOT_FOLDER_ID'];
const missing = required.filter((name) => !process.env[name]?.trim());

function md(value) {
  return String(value ?? '').replaceAll('|', '\\|').replace(/[\r\n]+/g, ' ').trim();
}

async function summarize(markdown) {
  if (summaryPath) await fs.appendFile(summaryPath, `${markdown}\n`, 'utf8');
  console.log(markdown.replace(/\n/g, ' | '));
}

if (missing.length) {
  await summarize(`## فحص أرشيف Drive\nلم يبدأ الفحص؛ أضف أسرار GitHub التالية لتفعيله: ${missing.map((x) => `\`${x}\``).join('، ')}. لم يُجر أي اتصال بـDrive.`);
  process.exit(0);
}

async function fetchJson(url, options = {}, attempts = 5) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let response;
    try {
      response = await fetch(url, { ...options, signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      lastError = error;
      if (attempt === attempts - 1) break;
      await new Promise((resolve) => setTimeout(resolve, 500 * (2 ** attempt)));
      continue;
    }

    const body = await response.text();
    let data;
    try { data = body ? JSON.parse(body) : {}; } catch { data = { error: { message: body.slice(0, 400) } }; }
    if (response.ok) return data;
    const error = new Error(data?.error?.message || `HTTP ${response.status}`);
    if (![429, 500, 502, 503, 504].includes(response.status) || attempt === attempts - 1) throw error;
    lastError = error;
    await new Promise((resolve) => setTimeout(resolve, 500 * (2 ** attempt)));
  }
  throw lastError || new Error('تعذر الاتصال بخدمة Google Drive.');
}

let serviceAccount;
try { serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON); }
catch { throw new Error('سر GOOGLE_SERVICE_ACCOUNT_JSON ليس ملف JSON صالحاً.'); }
if (!serviceAccount.client_email || !serviceAccount.private_key) throw new Error('ملف حساب الخدمة لا يتضمن client_email وprivate_key.');

const base64url = (value) => Buffer.from(value).toString('base64url');
const issuedAt = Math.floor(Date.now() / 1000);
const jwtHeader = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
const jwtClaims = base64url(JSON.stringify({
  iss: serviceAccount.client_email,
  scope: 'https://www.googleapis.com/auth/drive.metadata.readonly',
  aud: 'https://oauth2.googleapis.com/token',
  iat: issuedAt,
  exp: issuedAt + 3600,
}));
const unsignedJwt = `${jwtHeader}.${jwtClaims}`;
const signer = createSign('RSA-SHA256');
signer.update(unsignedJwt);
signer.end();
const assertion = `${unsignedJwt}.${signer.sign(serviceAccount.private_key, 'base64url')}`;
const token = await fetchJson('https://oauth2.googleapis.com/token', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion,
  }),
});
if (!token.access_token) throw new Error('لم تصدر Google رمز وصول لحساب الخدمة.');

const auth = { authorization: `Bearer ${token.access_token}` };
const folderQueue = [{ id: process.env.DRIVE_ROOT_FOLDER_ID.trim(), path: '' }];
const visitedFolders = new Set();
const current = new Map();

async function listChildren(folderId) {
  const items = [];
  let pageToken = '';
  do {
    const params = new URLSearchParams({
      q: `'${folderId}' in parents and trashed = false`,
      pageSize: '1000',
      fields: 'nextPageToken,files(id,name,mimeType,modifiedTime,size,md5Checksum)',
      supportsAllDrives: 'true',
      includeItemsFromAllDrives: 'true',
    });
    if (pageToken) params.set('pageToken', pageToken);
    const data = await fetchJson(`https://www.googleapis.com/drive/v3/files?${params}`, { headers: auth });
    items.push(...(data.files || []));
    pageToken = data.nextPageToken || '';
  } while (pageToken);
  return items;
}

while (folderQueue.length) {
  const folder = folderQueue.shift();
  if (visitedFolders.has(folder.id)) continue;
  visitedFolders.add(folder.id);
  const children = await listChildren(folder.id);
  for (const item of children) {
    const itemPath = folder.path ? `${folder.path}/${item.name}` : item.name;
    if (item.mimeType === 'application/vnd.google-apps.folder') {
      folderQueue.push({ id: item.id, path: itemPath });
      continue;
    }
    if (item.mimeType !== 'application/pdf') continue;
    const key = createHash('sha256').update(item.id).digest('hex');
    current.set(key, {
      name: item.name,
      folder: folder.path,
      modifiedTime: item.modifiedTime || '',
      size: item.size || '0',
      md5Checksum: item.md5Checksum || '',
    });
  }
}

await fs.mkdir(path.dirname(statePath), { recursive: true });
let previous = {};
let hadBaseline = false;
try {
  const parsed = JSON.parse(await fs.readFile(statePath, 'utf8'));
  if (parsed.schemaVersion === 1 && parsed.files && typeof parsed.files === 'object') {
    previous = parsed.files;
    hadBaseline = true;
  }
} catch (error) {
  if (error.code !== 'ENOENT') throw new Error('ملف حالة المزامنة تالف؛ أوقف الفحص حفاظاً على الحالة السابقة.');
}

const added = [];
const changed = [];
const removed = [];
if (hadBaseline) {
  for (const [key, file] of current) {
    const old = previous[key];
    if (!old) added.push(file);
    else if (old.modifiedTime !== file.modifiedTime || old.size !== file.size || old.md5Checksum !== file.md5Checksum || old.folder !== file.folder) changed.push(file);
  }
  for (const [key, file] of Object.entries(previous)) if (!current.has(key)) removed.push(file);
}

await fs.writeFile(statePath, `${JSON.stringify({ schemaVersion: 1, files: Object.fromEntries([...current.entries()].sort(([a], [b]) => a.localeCompare(b))) }, null, 2)}\n`, 'utf8');

const date = new Date().toISOString();
if (!hadBaseline) {
  await summarize(`## فحص أرشيف Drive\nأنشئت نقطة أساس بتاريخ ${date} تضم ${current.size} ملف PDF. لم تُنزّل الملفات ولم تُعالج ولم تُنشر.`);
} else {
  const rows = [...added.map((f) => ['جديد', f]), ...changed.map((f) => ['معدّل', f]), ...removed.map((f) => ['أزيل من Drive', f])];
  const table = rows.length
    ? `\n| الحالة | المجلد | الملف | آخر تعديل | الحجم |\n|---|---|---|---|---:|\n${rows.slice(0, 200).map(([status, file]) => `| ${status} | ${md(file.folder || 'الجذر')} | ${md(file.name)} | ${md(file.modifiedTime)} | ${md(file.size)} |`).join('\n')}${rows.length > 200 ? `\n\nعُرض أول 200 من ${rows.length} تغييراً.` : ''}`
    : '\nلا توجد ملفات جديدة أو معدّلة أو محذوفة منذ الفحص السابق.';
  await summarize(`## فحص أرشيف Drive — ${date}\n- ملفات PDF الحالية: ${current.size}\n- جديدة: ${added.length}؛ معدّلة: ${changed.length}؛ أزيلت: ${removed.length}\n- هذه مرحلة رصد فقط: لا تنزيل، ولا OCR، ولا تعديل في Drive أو نشر للمكتبة.${table}`);
}
