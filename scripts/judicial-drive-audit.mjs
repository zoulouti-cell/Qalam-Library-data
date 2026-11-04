import fs from 'node:fs/promises';
import path from 'node:path';
import { createSign } from 'node:crypto';

const ROOT_ID = process.env.DRIVE_JUDICIAL_FOLDER_ID?.trim();
const SA_JSON = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
const API = process.env.JURIS_CASSATION_API || 'https://huquqai.ma/api/juriscassation';
const PAGE_SIZE = 100;
const CONCURRENCY = 5;

function assertConfig() {
  if (!ROOT_ID || !SA_JSON) throw new Error('أضف DRIVE_JUDICIAL_FOLDER_ID و GOOGLE_SERVICE_ACCOUNT_JSON إلى أسرار Actions.');
}

async function getJson(url, options = {}, retries = 6) {
  let last;
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(45_000) });
      const text = await response.text();
      let body;
      try { body = text ? JSON.parse(text) : {}; } catch { body = { error: text.slice(0, 500) }; }
      if (response.ok) return body;
      const retryable = [408, 425, 429, 500, 502, 503, 504].includes(response.status);
      const error = Object.assign(new Error(body?.error?.message || `HTTP ${response.status} (${url})`), { retryable });
      if (!retryable || i === retries - 1) throw error;
      last = error;
    } catch (error) {
      if (error.retryable === false) throw error;
      last = error;
      if (i === retries - 1) break;
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(20_000, 700 * (2 ** i))));
  }
  throw last || new Error('تعذر الاتصال بالمصدر.');
}

async function getGoogleToken() {
  let account;
  try { account = JSON.parse(SA_JSON); } catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON ليس JSON صالحاً.'); }
  if (!account.client_email || !account.private_key) throw new Error('بيانات حساب الخدمة ناقصة.');
  const b64 = value => Buffer.from(value).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const head = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64(JSON.stringify({ iss: account.client_email, scope: 'https://www.googleapis.com/auth/drive.metadata.readonly', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const unsigned = `${head}.${claims}`;
  const signer = createSign('RSA-SHA256'); signer.update(unsigned); signer.end();
  const assertion = `${unsigned}.${signer.sign(account.private_key, 'base64url')}`;
  const token = await getJson('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  if (!token.access_token) throw new Error('لم تصدر Google رمز وصول للقراءة.');
  return { authorization: `Bearer ${token.access_token}` };
}

async function listFolder(folderId, headers) {
  const files = [];
  let pageToken = '';
  do {
    const q = new URLSearchParams({
      q: `'${folderId}' in parents and trashed = false`,
      pageSize: '1000',
      fields: 'nextPageToken,files(id,name,mimeType,modifiedTime,size,webViewLink,parents)',
      supportsAllDrives: 'true', includeItemsFromAllDrives: 'true',
    });
    if (pageToken) q.set('pageToken', pageToken);
    const page = await getJson(`https://www.googleapis.com/drive/v3/files?${q}`, { headers });
    files.push(...(page.files || []));
    pageToken = page.nextPageToken || '';
  } while (pageToken);
  return files;
}

async function scanDrive(headers) {
  const queue = [{ id: ROOT_ID, path: '' }];
  const visited = new Set();
  const pdfs = [];
  while (queue.length) {
    const folder = queue.shift();
    if (visited.has(folder.id)) continue;
    visited.add(folder.id);
    const items = await listFolder(folder.id, headers);
    for (const item of items) {
      const itemPath = folder.path ? `${folder.path}/${item.name}` : item.name;
      if (item.mimeType === 'application/vnd.google-apps.folder') queue.push({ id: item.id, path: itemPath });
      else if (item.mimeType === 'application/pdf') pdfs.push({ ...item, path: itemPath });
    }
    if (visited.size % 50 === 0) console.log(`Drive folders scanned: ${visited.size}; PDFs: ${pdfs.length}`);
  }
  return pdfs;
}

async function getSourceDecisions() {
  const first = await getJson(`${API}?page=1&limit=${PAGE_SIZE}`, { headers: { accept: 'application/json', 'user-agent': 'Qalam-Library-Judicial-Audit/1.0' } });
  const total = Number(first.totalCount || first.total || 0);
  if (!Array.isArray(first.data) || !total) throw new Error('لم يرجع مصدر القرارات قائمةً مفهومةً أو إجماليها.');
  const pages = Math.ceil(total / PAGE_SIZE);
  const records = [...first.data];
  const failed = [];
  let nextPage = 2;
  const workers = Array.from({ length: CONCURRENCY }, async () => {
    while (true) {
      const page = nextPage++;
      if (page > pages) return;
      try {
        const data = await getJson(`${API}?page=${page}&limit=${PAGE_SIZE}`, { headers: { accept: 'application/json', 'user-agent': 'Qalam-Library-Judicial-Audit/1.0' } });
        if (!Array.isArray(data.data)) throw new Error(`page ${page}: missing data[]`);
        records.push(...data.data);
      } catch (error) { failed.push({ page, error: String(error.message || error) }); }
      if (page % 50 === 0 || page === pages) console.log(`Source pages scanned: ${page}/${pages}`);
    }
  });
  await Promise.all(workers);
  if (failed.length) throw new Error(`تعذر جلب ${failed.length} صفحة من أصل ${pages}؛ لن يُصدر تقرير ناقص. أمثلة: ${failed.slice(0, 5).map(x => `${x.page}: ${x.error}`).join(' | ')}`);
  const byId = new Map(records.map(record => [String(record.id), record]));
  const sourceGap = Math.max(0, total - byId.size);
  if (sourceGap) console.warn(`تحذير المصدر: الإجمالي المعلن ${total}، لكن الصفحات أعادت ${byId.size} سجلاً فريداً (فارق ${sourceGap}). سيقتصر التدقيق على السجلات المعادة ويُبيّن هذا القيد صراحةً.`);
  return { total, returned: records.length, unique: byId.size, sourceGap, records: [...byId.values()] };
}

function clean(s) { return String(s ?? '').normalize('NFKC').trim().replace(/\s+/g, ' '); }
function destination(record) {
  const level = clean(record.court_level).toLowerCase();
  const name = clean(record.court_name);
  const year = Number(String(record.decision_date || '').slice(0, 4));
  if (level === 'cassation' || name === 'محكمة النقض' || name === 'المجلس الأعلى') {
    if (name === 'المجلس الأعلى' && year > 0 && year < 2012) return { path: 'الاجتهادات القضائية/المجلس الاعلى', confidence: 'مرتفع: تسمية المجلس وسنة القرار' };
    if (name === 'المجلس الأعلى' && year === 2011) return { path: '', confidence: 'مراجعة أصل القرار: سنة انتقالية' };
    return { path: 'الاجتهادات القضائية/محكمة النقض', confidence: name === 'المجلس الأعلى' ? 'مرتفع: مستوى النقض والسنة بعد 2011' : 'مرتفع: اسم محكمة النقض/مستوى النقض' };
  }
  if (name.startsWith('محكمة الاستئناف')) return { path: `الاجتهادات القضائية/محاكم الدرجة الثانية/${name}`, confidence: 'مرتفع: اسم المحكمة في بيانات المصدر' };
  if (name.startsWith('المحكمة الإدارية') || name.startsWith('المحكمة التجارية')) return { path: `الاجتهادات القضائية/محاكم الدرجة الاولى/${name}`, confidence: 'مرتفع: اسم المحكمة في بيانات المصدر' };
  return { path: '', confidence: 'مراجعة بشرية: اسم أو مستوى المحكمة غير محسوم' };
}

function csvCell(v) { return `"${String(v ?? '').replaceAll('"', '""').replace(/[\r\n]+/g, ' ')}"`; }
function writeCsv(file, rows, fields) {
  return fs.writeFile(file, `\uFEFF${[fields.join(','), ...rows.map(row => fields.map(key => csvCell(row[key])).join(','))].join('\r\n')}\r\n`, 'utf8');
}

assertConfig();
console.log('Fetching Court of Cassation source metadata…');
const [source, token] = await Promise.all([getSourceDecisions(), getGoogleToken()]);
console.log(`Source: ${source.records.length}/${source.total} records; scanning Drive read-only…`);
const driveFiles = await scanDrive(token);
const byId = new Map();
for (const file of driveFiles) {
  const match = file.name.match(/^(\d+)\.pdf$/i);
  if (!match) continue;
  const list = byId.get(match[1]) || [];
  list.push(file); byId.set(match[1], list);
}

const rows = source.records.map(record => {
  const id = String(record.id);
  const files = byId.get(id) || [];
  const target = destination(record);
  const paths = files.map(file => file.path);
  let status = 'موجود في Drive لكن يحتاج مراجعة موقعه';
  if (!files.length) status = 'غير موجود في Drive';
  else if (files.length > 1) status = 'مكرر في Drive';
  else if (target.path && paths[0].startsWith(`${target.path}/`)) status = 'موجود في المجلد الصحيح';
  else if (!target.path) status = 'يحتاج تحديد المحكمة من أصل القرار';
  else status = 'موجود في مجلد غير مطابق';
  return {
    record_id: id,
    court_name: record.court_name || '',
    court_level: record.court_level || '',
    decision_number: record.decision_number || '',
    case_number: record.case_number || '',
    decision_date: String(record.decision_date || '').slice(0, 10),
    target_folder: target.path,
    confidence: target.confidence,
    status,
    drive_locations: paths.join(' ؛ '),
    drive_file_ids: files.map(file => file.id).join(' '),
    official_pdf_url: record.pdf_url || '',
  };
});

const tally = new Map();
for (const row of rows) {
  const key = row.court_name || `غير محدد (${row.court_level || 'مستوى مجهول'})`;
  const group = tally.get(key) || { court: key, source_records: 0, in_drive_correct: 0, misplaced: 0, missing_from_drive: 0, duplicate_in_drive: 0, needs_review: 0 };
  group.source_records++;
  if (row.status === 'موجود في المجلد الصحيح') group.in_drive_correct++;
  else if (row.status === 'موجود في مجلد غير مطابق') group.misplaced++;
  else if (row.status === 'غير موجود في Drive') group.missing_from_drive++;
  else if (row.status === 'مكرر في Drive') group.duplicate_in_drive++;
  else group.needs_review++;
  tally.set(key, group);
}

const out = path.resolve(process.env.RUNNER_TEMP || process.cwd());
await writeCsv(path.join(out, 'judicial-drive-audit.csv'), rows, ['record_id','court_name','court_level','decision_number','case_number','decision_date','target_folder','confidence','status','drive_locations','drive_file_ids','official_pdf_url']);
await writeCsv(path.join(out, 'judicial-drive-summary.csv'), [...tally.values()].sort((a,b) => a.court.localeCompare(b.court, 'ar')), ['court','source_records','in_drive_correct','misplaced','missing_from_drive','duplicate_in_drive','needs_review']);
const totals = rows.reduce((a, row) => { a[row.status] = (a[row.status] || 0) + 1; return a; }, {});
const summary = [
  '# تدقيق القرارات القضائية مقابل Google Drive',
  '',
  `- تاريخ الفحص: ${new Date().toISOString()}`,
  `- سجلات المصدر الفريدة المفحوصة: ${source.unique} (المعاد من الصفحات: ${source.returned}؛ الإجمالي المعلن: ${source.total}؛ الفارق غير المتاح من المصدر: ${source.sourceGap})`,
  `- ملفات PDF المفحوصة في شجرة Drive: ${driveFiles.length}`,
  ...Object.entries(totals).map(([status, count]) => `- ${status}: ${count}`),
  '',
  'هذا التدقيق للقراءة فقط. لم ينقل الملفات ولم يرفع أو يحذف أي مستند. ملف CSV التفصيلي يربط كل سجل بمساره الحالي ورابط PDF الرسمي ومجلد الوجهة المقترح.',
].join('\n');
await fs.writeFile(path.join(out, 'judicial-drive-summary.md'), `${summary}\n`, 'utf8');
const ghSummary = process.env.GITHUB_STEP_SUMMARY;
if (ghSummary) await fs.appendFile(ghSummary, `${summary}\n\nتقرير تفصيلي مرفق مع تشغيل Actions.\n`, 'utf8');
console.log(summary);

