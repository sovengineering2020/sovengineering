const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const archiver = require('archiver');
const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');
const { isDeepStrictEqual } = require('util');

const app = express();

app.use(cors());
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || '70mb' }));

const port = process.env.PORT || 3000;
const MAX_DATE_RANGE_MONTHS = Math.max(1, Number(process.env.MAX_DATE_RANGE_MONTHS || 3));

const CSV_ROOT = path.resolve(
  process.env.CSV_STORAGE_DIR ||
  path.join(__dirname, 'data', 'csv')
);

const MONTHLY_DIR = path.join(
  CSV_ROOT,
  'monthly'
);

const FY_DIR = path.join(
  CSV_ROOT,
  'financial-years'
);

const INDEX_FILE = path.join(
  CSV_ROOT,
  '_index.csv'
);

const DAILY_DIR = path.join(CSV_ROOT, 'daily');
// Fast operational read store. Encrypted JSON is partitioned by entity/year/month/ID bucket.
// CSV remains the migration/recovery/export layer; employee JSON handling is intentionally separate.
const JSON_STORE_ROOT = path.join(CSV_ROOT, 'operational-json');
const JSON_STORE_BUCKETS = Math.max(16, Math.min(1024, Number(process.env.JSON_STORE_BUCKETS || 256)));
// These manual Admin operations are disabled by default. Only the explicit
// case-insensitive string value "true" enables each feature.
function envFlagEnabled(name) { return String(process.env[name] ?? '').trim().toLowerCase() === 'true'; }
// The former manual CSV-to-JSON migration trigger is disabled in the daily-login workflow.
// Keep the legacy recovery implementation available only behind a distinct break-glass flag.
const ENABLE_LEGACY_CSV_JSON_RECOVERY = envFlagEnabled('ENABLE_LEGACY_CSV_JSON_RECOVERY');
const ENABLE_JSON_BACKUP = envFlagEnabled('ENABLE_JSON_BACKUP');
// The daily directory now contains one encrypted Previous/Pending JSON
// synchronization buffer. Legacy daily JSON files are migrated once at startup.
const DAILY_JSON_GITHUB_DIR = safeString(process.env.GITHUB_DAILY_JSON_DIR || 'daily').replace(/^\/+|\/+$/g, '');

/* ---------------------------------------------------------
 * Drawings persistence (single active PDF + searchable page index)
 * --------------------------------------------------------- */
const DRAWINGS_DIR = path.join(CSV_ROOT, 'drawings');
const DRAWING_PDF_LOCAL = path.join(DRAWINGS_DIR, 'drawings.pdf.enc');
const DRAWING_INDEX_LOCAL = path.join(DRAWINGS_DIR, 'index.json.enc');
const DRAWINGS_GITHUB_PATH = 'data/drawings';
const DRAWING_PDF_GITHUB_FILE = 'drawings.pdf';
const DRAWING_INDEX_GITHUB_FILE = 'index.json';
const MAX_DRAWING_PDF_BYTES = Math.max(1, Number(process.env.MAX_DRAWING_PDF_MB || 50)) * 1024 * 1024;

const CSV_HEADERS = [
  'entity',
  'id',
  'date',
  'financial_year',
  'updated_at',
  'payload'
];

const INDEX_HEADERS = [
  'entity',
  'id',
  'month',
  'financial_year',
  'updated_at'
];

const EMPLOYEE_KEY = 'fl_employees';

/* Serialize employee writes so server-side Employee ID generation
 * is atomic within this Node.js server process. */
let employeeWriteQueue = Promise.resolve();

function withEmployeeWriteLock(task) {
  if (jsonMigrationCommitInProgress) return (jsonMigrationCommitWaiter || Promise.resolve()).then(() => withEmployeeWriteLock(task));
  const run = employeeWriteQueue.then(task, task);
  employeeWriteQueue = run.catch(() => {});
  return run;
}

const NON_EMPLOYEE_KEYS = [
  'fl_workorders',
  'fl_workhistory',
  'fl_attendance',
  'fl_permissions',
  'fl_leaves',
  'fl_sundayot',
  'fl_finance',
  'fl_powercuts',
  'fl_invoices',
  'fl_partsamounts',
  'fl_doctemplates'
];

/* ---------------------------------------------------------
 * Basic helpers
 * --------------------------------------------------------- */

function safeString(value) {
  return value == null ? '' : String(value);
}

function appTodayStr() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: process.env.APP_TIMEZONE || 'Asia/Kolkata' }).format(new Date());
}

function json(value) {
  return JSON.stringify(value ?? null);
}

function encryptionKey() {
  const raw = safeString(
    process.env.CSV_ENCRYPTION_KEY
  ).trim();

  if (!raw) {
    throw new Error(
      'CSV_ENCRYPTION_KEY environment variable is missing.'
    );
  }

  return crypto
    .createHash('sha256')
    .update(raw, 'utf8')
    .digest();
}

/* ---------------------------------------------------------
 * Encrypted CSV
 * --------------------------------------------------------- */

function encryptText(plainText) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    encryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(
      String(plainText),
      'utf8'
    ),
    cipher.final()
  ]);

  const authTag =
    cipher.getAuthTag();

  return [
    'SOVCSV1',
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64')
  ].join(':');
}

function decryptText(storedText) {
  const text = safeString(storedText);

  if (!text.startsWith('SOVCSV1:')) {
    return text;
  }

  const parts = text.split(':');

  if (parts.length !== 4) {
    throw new Error(
      'Invalid encrypted CSV format.'
    );
  }

  const iv = Buffer.from(
    parts[1],
    'base64'
  );

  const authTag = Buffer.from(
    parts[2],
    'base64'
  );

  const encrypted = Buffer.from(
    parts[3],
    'base64'
  );

  const decipher =
    crypto.createDecipheriv(
      'aes-256-gcm',
      encryptionKey(),
      iv
    );

  decipher.setAuthTag(authTag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString('utf8');
}

function encryptBuffer(plainBuffer) {
  const input = Buffer.isBuffer(plainBuffer) ? Buffer.from(plainBuffer) : Buffer.from(plainBuffer || []);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('SOVBIN1', 'ascii'), iv, authTag, encrypted]);
}

function decryptBuffer(storedBuffer) {
  const input = Buffer.isBuffer(storedBuffer) ? storedBuffer : Buffer.from(storedBuffer || []);
  if (input.subarray(0, 7).toString('ascii') !== 'SOVBIN1' || input.length < 35) {
    throw new Error('Invalid encrypted drawing PDF format.');
  }
  const iv = input.subarray(7, 19);
  const authTag = input.subarray(19, 35);
  const encrypted = input.subarray(35);
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/* ---------------------------------------------------------
 * CSV parsing / writing
 * --------------------------------------------------------- */

function csvEscape(value) {
  const s = safeString(value);

  return /[",\n\r]/.test(s)
    ? `"${s.replace(/"/g, '""')}"`
    : s;
}

function parseCsv(text) {
  if (!text || !text.trim()) {
    return [];
  }

  const rows = [];

  let row = [];
  let field = '';
  let quoted = false;

  for (
    let i = 0;
    i < text.length;
    i++
  ) {
    const ch = text[i];

    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += ch;
      }

      continue;
    }

    if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch === '\r') {
      if (text[i + 1] !== '\n') {
        row.push(field);
        rows.push(row);
        row = [];
        field = '';
      }
    } else {
      field += ch;
    }
  }

  if (
    field !== '' ||
    row.length
  ) {
    row.push(field);
    rows.push(row);
  }

  if (!rows.length) {
    return [];
  }

  const headers = rows[0];

  return rows
    .slice(1)
    .filter(row =>
      row.some(
        value => value !== ''
      )
    )
    .map(row => {
      const object = {};

      headers.forEach(
        (header, index) => {
          object[header] =
            row[index] ?? '';
        }
      );

      return object;
    });
}

function storedContentPlainText(value) {
  const text = safeString(value);
  if (!text) return '';
  try {
    return text.startsWith('SOVCSV1:') ? decryptText(text) : text;
  } catch (_) {
    return text;
  }
}

function normalizeStoredContentForCompare(value) {
  return storedContentPlainText(value)
    .replace(/^\uFEFF/, '')
    .replace(/\r\n?/g, '\n');
}

function sameStoredContent(a, b) {
  return normalizeStoredContentForCompare(a) === normalizeStoredContentForCompare(b);
}

// GitHub's Contents API may normalize trailing newlines or JSON formatting on
// read-back. For migration markers, verify the parsed document as well as the
// byte-normalized text so harmless formatting differences do not fail a valid commit.
function sameJsonDocument(a, b) {
  try {
    return isDeepStrictEqual(JSON.parse(String(a)), JSON.parse(String(b)));
  } catch (_) {
    return sameStoredContent(a, b);
  }
}

async function verifyGitHubJsonDocument(relativePath, expectedContent, label) {
  let lastRemote = null;
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      lastRemote = await githubReadFile(relativePath);
      if (lastRemote?.content != null && sameJsonDocument(lastRemote.content, expectedContent)) {
        return { ok: true, attempt, sha: lastRemote.sha || null };
      }
    } catch (error) {
      lastError = error;
    }
    if (attempt < 3) await new Promise(resolve => setTimeout(resolve, 250 * attempt));
  }
  const remoteText = safeString(lastRemote?.content);
  const expectedText = safeString(expectedContent);
  const remoteDigest = remoteText ? crypto.createHash('sha256').update(remoteText).digest('hex').slice(0, 16) : 'missing';
  const expectedDigest = expectedText ? crypto.createHash('sha256').update(expectedText).digest('hex').slice(0, 16) : 'empty';
  throw new Error(`${label} verification failed after 3 read-back attempts (expected sha256=${expectedDigest}, remote sha256=${remoteDigest}${lastError ? `, last read error=${lastError.message}` : ''}).`);
}

function storedContentDiagnostic(value) {
  const raw = safeString(value);
  const plain = normalizeStoredContentForCompare(raw);
  return {
    present: value != null && raw.length > 0,
    rawLength: Buffer.byteLength(raw, 'utf8'),
    normalizedLength: Buffer.byteLength(plain, 'utf8'),
    rawSha256: crypto.createHash('sha256').update(raw, 'utf8').digest('hex').slice(0, 16),
    normalizedSha256: crypto.createHash('sha256').update(plain, 'utf8').digest('hex').slice(0, 16),
    encrypted: raw.startsWith('SOVCSV1:')
  };
}

function writeCsvFile(
  filePath,
  headers,
  rows
) {
  const plain = [
    headers.join(','),
    ...rows.map(row =>
      headers
        .map(header =>
          csvEscape(row[header])
        )
        .join(',')
    )
  ].join('\n') + '\n';

  const existing = fs.existsSync(filePath)
    ? fs.readFileSync(filePath, 'utf8')
    : '';

  // Encryption uses a random IV, so ciphertext changes even when the actual
  // CSV data is identical. Compare the plaintext first and do not touch the
  // file when there is no real data change.
  if (existing && sameStoredContent(existing, plain)) {
    return false;
  }

  const encrypted =
    encryptText(plain);

  const tempFile =
    `${filePath}.tmp-${process.pid}-${Date.now()}`;

  fs.writeFileSync(
    tempFile,
    encrypted,
    'utf8'
  );

  fs.renameSync(
    tempFile,
    filePath
  );
  return true;
}

function readCsvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const raw =
    fs.readFileSync(
      filePath,
      'utf8'
    );

  const plain =
    decryptText(raw);

  // Reading a legacy plaintext CSV must not itself cause a write. Any
  // migration to encrypted storage happens only inside an explicit durable
  // persistence operation.
  return parseCsv(plain);
}

function ensureCsvDirs() {
  fs.mkdirSync(
    MONTHLY_DIR,
    {
      recursive: true
    }
  );

  fs.mkdirSync(
    FY_DIR,
    {
      recursive: true
    }
  );

  fs.mkdirSync(DAILY_DIR, { recursive: true });

  if (!fs.existsSync(INDEX_FILE)) {
    writeCsvFile(
      INDEX_FILE,
      INDEX_HEADERS,
      []
    );
  }
}

/* ---------------------------------------------------------
 * Date / financial-year helpers
 * --------------------------------------------------------- */

function monthFor(dateValue) {
  const raw =
    safeString(dateValue)
      .slice(0, 10);

  if (
    /^\d{4}-\d{2}-\d{2}$/.test(raw)
  ) {
    return raw.slice(0, 7);
  }

  return new Date()
    .toISOString()
    .slice(0, 7);
}

function fyFor(dateValue) {
  const month =
    monthFor(dateValue);

  const year =
    Number(month.slice(0, 4));

  const monthNumber =
    Number(month.slice(5, 7));

  const startYear =
    monthNumber >= 4
      ? year
      : year - 1;

  return `${startYear}-${startYear + 1}`;
}

function monthlyFile(month) {
  return path.join(
    MONTHLY_DIR,
    `${month}.csv`
  );
}

function financialYearFile(fy) {
  return path.join(
    FY_DIR,
    `${fy}.csv`
  );
}

/* ---------------------------------------------------------
 * Record identity
 * --------------------------------------------------------- */

function recordId(record) {
  return safeString(
    record?.id
  ).trim();
}

function recordDate(
  entity,
  record
) {
  if (
    !record ||
    typeof record !== 'object'
  ) {
    return new Date()
      .toISOString()
      .slice(0, 10);
  }

  const candidates = [
    record.date,
    record.entryDate,
    record.workDate,
    record.attendanceDate,
    record.requestDate,
    record.startDate,
    record.otDate,
    record.powerDate,
    record.paymentDate,
    record.advanceDate,
    record.poDate,

    record.salaryPeriod
      ? `${record.salaryPeriod}-01`
      : '',

    record.createdAt,
    record.updatedAt
  ];

  for (
    const value of candidates
  ) {
    const valueString =
      safeString(value);

    if (
      /^\d{4}-\d{2}-\d{2}/.test(
        valueString
      )
    ) {
      return valueString.slice(
        0,
        10
      );
    }

    if (
      /^\d{4}-\d{2}$/.test(
        valueString
      )
    ) {
      return `${valueString}-01`;
    }
  }

  return new Date()
    .toISOString()
    .slice(0, 10);
}

/* ---------------------------------------------------------
 * Soft-delete helpers
 * --------------------------------------------------------- */

function normalizeIsDeleted(record) {
  if (
    !record ||
    typeof record !== 'object'
  ) {
    return record;
  }

  if (
    record.isDeleted !== true
  ) {
    record.isDeleted = false;
  }

  return record;
}

function isDeleted(record) {
  return (
    record?.isDeleted === true ||
    safeString(
      record?.isDeleted
    ).toLowerCase() === 'true' ||
    safeString(
      record?.isDeleted
    ) === '1'
  );
}

function activeRecord(record) {
  return (
    record &&
    !isDeleted(record)
  );
}

function ensureSoftDeleteField(
  records
) {
  return (
    Array.isArray(records)
      ? records
      : []
  ).map(record =>
    normalizeIsDeleted({
      ...record
    })
  );
}

/*
 * The application must never physically delete a
 * CSV record. Delete means only setting isDeleted=true.
 */
function softDeleteRecord(
  records,
  id
) {
  const targetId =
    safeString(id).trim();

  return (
    Array.isArray(records)
      ? records
      : []
  ).map(record => {
    if (
      recordId(record) ===
      targetId
    ) {
      return {
        ...record,
        isDeleted: true,
        updatedAt:
          new Date().toISOString()
      };
    }

    return normalizeIsDeleted({
      ...record
    });
  });
}

/* ---------------------------------------------------------
 * CSV row conversion
 * --------------------------------------------------------- */

function rowFromRecord(
  entity,
  record
) {
  const normalized =
    normalizeIsDeleted({
      ...record
    });

  const date =
    recordDate(
      entity,
      normalized
    );

  return {
    entity,
    id: recordId(normalized),
    date,
    financial_year:
      fyFor(date),
    updated_at:
      new Date().toISOString(),
    payload:
      json(normalized)
  };
}

function rowToRecord(row) {
  try {
    const record =
      JSON.parse(
        row.payload
      );

    if (
      !record ||
      typeof record !== 'object'
    ) {
      return null;
    }

    return normalizeIsDeleted(
      record
    );
  } catch (_) {
    return null;
  }
}

function entityRowsFromFile(
  filePath,
  entity
) {
  return readCsvFile(filePath)
    .filter(
      row =>
        row.entity === entity &&
        row.id
    )
    .map(row => ({
      ...row,
      record:
        rowToRecord(row)
    }))
    .filter(
      row =>
        row.record !== null
    );
}

/* ---------------------------------------------------------
 * Index
 * --------------------------------------------------------- */

function loadIndex() {
  ensureCsvDirs();

  return readCsvFile(
    INDEX_FILE
  );
}

function saveIndex(rows) {
  ensureCsvDirs();
  return writeCsvFile(INDEX_FILE, INDEX_HEADERS, rows);
}

function updateIndexForEntity(
  entity,
  records
) {
  const existingIndex = loadIndex();
  const index = existingIndex.filter(
    row =>
      row.entity !== entity
  );

  const existingById = new Map(
    existingIndex
      .filter(row => row.entity === entity && row.id)
      .map(row => [row.id, row])
  );

  const rows =
    ensureSoftDeleteField(
      records
    )
      .map(record => {
        const date =
          recordDate(
            entity,
            record
          );
        const id = recordId(record);
        const previous = existingById.get(id);
        const recordTimestamp = safeString(
          record?.updatedAt ||
          record?.updated_at ||
          record?.createdAt ||
          record?.created_at
        ).trim();

        return {
          entity,
          id,
          month: monthFor(date),
          financial_year: fyFor(date),
          // Preserve derived-index metadata when the record itself did not
          // change. This prevents an unchanged save from changing _index.csv.
          updated_at: recordTimestamp || previous?.updated_at || new Date().toISOString()
        };
      })
      .filter(
        row => row.id
      );

  return saveIndex([
    ...index,
    ...rows
  ]);
}

function getMonthsForEntity(
  entity
) {
  const months = new Set(
    loadIndex()
      .filter(row => row.entity === entity)
      .map(row => row.month)
      .filter(Boolean)
  );

  // The index is derived metadata, not the historical source of truth.
  // Always include locally restored monthly files so a stale/incomplete
  // index can never hide valid historical records.
  for (const month of getAllLocalMonthlyFiles()) months.add(month);
  return [...months];
}

function getFinancialYearsForEntity(
  entity
) {
  const years = new Set(
    loadIndex()
      .filter(row => row.entity === entity)
      .map(row => row.financial_year)
      .filter(Boolean)
  );

  // Also derive FY coverage from the actual local monthly files.
  for (const month of getAllLocalMonthlyFiles()) years.add(fyFor(`${month}-01`));
  return [...years];
}

/* ---------------------------------------------------------
 * Employee ID helpers
 * --------------------------------------------------------- */

function employeeIdOf(employee) {
  if (!employee) {
    return '';
  }

  return safeString(
    employee.id ??
    employee.employeeId
  ).trim();
}

function employeeCodeOf(employee) {
  return safeString(
    employee.code ??
    employee.employeeCode
  ).trim();
}

function normalizeEmployee(
  employee
) {
  if (
    !employee ||
    typeof employee !== 'object'
  ) {
    return null;
  }

  const normalized = {
    ...employee
  };

  normalized.id =
    employeeIdOf(employee);

  /*
   * Employee Code remains a separate field.
   * It is never used as the unique employee key.
   */
  if (
    normalized.code == null &&
    normalized.employeeCode != null
  ) {
    normalized.code =
      safeString(
        normalized.employeeCode
      );
  }

  if (
    normalized.employeeCode == null &&
    normalized.code != null
  ) {
    normalized.employeeCode =
      safeString(
        normalized.code
      );
  }

  normalized.isDeleted =
    normalized.isDeleted === true;

  return normalized;
}

function employeeIdFromReference(
  value
) {
  if (
    value &&
    typeof value === 'object'
  ) {
    return employeeIdOf(value);
  }

  return safeString(value).trim();
}

function normalizeEmployeeReferenceRecord(
  record,
  employeeMap
) {
  if (
    !record ||
    typeof record !== 'object'
  ) {
    return record;
  }

  const output = {
    ...record
  };

  const possibleFields = [
    'employeeId',
    'workerId',
    'assignedEmployeeId',
    'employeeID',
    'workerID'
  ];

  for (
    const field of possibleFields
  ) {
    if (
      output[field] != null &&
      typeof output[field] === 'object'
    ) {
      output[field] =
        employeeIdFromReference(
          output[field]
        );
    }
  }

  if (
    Array.isArray(
      output.assignedTo
    )
  ) {
    output.assignedTo =
      output.assignedTo
        .map(
          employeeIdFromReference
        )
        .filter(Boolean);
  } else if (
    output.assignedTo != null
  ) {
    output.assignedTo =
      employeeIdFromReference(
        output.assignedTo
      );
  }

  /*
   * Employee ID is the primary reference.
   * Existing Employee Code/name values are retained as
   * display data but are not converted into primary IDs.
   */
  const primary =
    safeString(
      output.employeeId ??
      output.workerId ??
      output.assignedEmployeeId
    ).trim();

  if (primary) {
    output.employeeId =
      primary;
  }

  /*
   * Resolve legacy records only when an actual Employee ID
   * is already present. Never guess an ID from a name/code.
   */
  if (
    output.employeeId &&
    employeeMap.has(
      output.employeeId
    )
  ) {
    const employee =
      employeeMap.get(
        output.employeeId
      );

    if (
      output.employeeName == null &&
      employee.name != null
    ) {
      output.employeeName =
        employee.name;
    }

    if (
      output.employeeCode == null &&
      employeeCodeOf(employee)
    ) {
      output.employeeCode =
        employeeCodeOf(employee);
    }
  }

  return normalizeIsDeleted(
    output
  );
}

function normalizeEmployeeReferences(
  records,
  employees
) {
  const employeeMap =
    new Map();

  for (
    const employee of
    ensureSoftDeleteField(
      employees
    )
      .map(normalizeEmployee)
      .filter(Boolean)
  ) {
    const id =
      employeeIdOf(employee);

    if (id) {
      employeeMap.set(
        id,
        employee
      );
    }
  }

  return (
    Array.isArray(records)
      ? records
      : []
  )
    .map(record =>
      normalizeEmployeeReferenceRecord(
        record,
        employeeMap
      )
    )
    .filter(Boolean)
    .filter(
      record =>
        !isDeleted(record)
    );
}

/* ---------------------------------------------------------
 * Employee sorting
 * --------------------------------------------------------- */

function employeeIdSortValue(
  employee
) {
  const id =
    employeeIdOf(employee);

  /*
   * Numeric IDs sort numerically.
   * Non-numeric IDs use natural string ordering.
   */
  if (
    /^\d+$/.test(id)
  ) {
    return {
      numeric: true,
      number: Number(id),
      text: id
    };
  }

  return {
    numeric: false,
    number: 0,
    text: id
  };
}

function compareEmployeeId(
  a,
  b
) {
  const av =
    employeeIdSortValue(a);

  const bv =
    employeeIdSortValue(b);

  if (
    av.numeric &&
    bv.numeric
  ) {
    return (
      av.number -
      bv.number
    );
  }

  if (
    av.numeric !==
    bv.numeric
  ) {
    return av.numeric
      ? -1
      : 1;
  }

  return av.text.localeCompare(
    bv.text,
    undefined,
    {
      numeric: true,
      sensitivity: 'base'
    }
  );
}

/* ---------------------------------------------------------
 * Persistent Previous/Pending JSON synchronization buffer
 * ---------------------------------------------------------
 * One encrypted JSON buffer is used for records that have not yet been
 * durably synchronized to CSV. It is intentionally independent of the
 * current date. Date changes never create, replace, or clear this buffer.
 */
let dailyState = { date: '', entities: {} };
let dailyStateLoaded = false;
let pendingState = { version: 2, updatedAt: '', entities: {} };
let pendingStateLoaded = false;
// Cache only previously verified bundle values; never fabricate records.
const lastSuccessfulStateBundleValues = new Map();
// All operational persistence mutations share one queue. This serializes
// Current/Pending JSON writes with the explicit CSV synchronization process,
// so a CSV sync can never clear a stale Pending snapshot after a newer user
// change has been accepted. It also protects monthly/FY CSV files, which may
// contain rows for multiple entities.
let durableCsvWriteQueue = Promise.resolve();
// CSV cache is retained for CSV migration/export/verification only. Routine operational
// reads use the encrypted, partitioned JSON store below.
const entityAllCsvCache = new Map();
const entityAllJsonCache = new Map();
function invalidateEntityCsvCache(entity) {
  if (entity) entityAllCsvCache.delete(entity);
  else entityAllCsvCache.clear();
}
function invalidateEntityJsonCache(entity) {
  if (entity) entityAllJsonCache.delete(entity);
  else entityAllJsonCache.clear();
}
function enqueueDurableCsvWrite(task) {
  if (jsonMigrationCommitInProgress) return (jsonMigrationCommitWaiter || Promise.resolve()).then(() => enqueueDurableCsvWrite(task));
  const run = durableCsvWriteQueue.then(task);
  durableCsvWriteQueue = run.catch(() => {});
  return run;
}

const PREVIOUS_PENDING_JSON_LOCAL = path.join(DAILY_DIR, 'previous-pending.json');
const PREVIOUS_PENDING_JSON_GITHUB = `${DAILY_JSON_GITHUB_DIR}/previous-pending.json`.replace(/^\/+/, '');
// Separate durable journal for changes that have reached year-wise JSON but still
// need the existing CSV/GitHub CSV synchronization workflow. This allows the
// year-wise migration to clear only verified records from Previous/Pending
// without losing the CSV synchronization queue.
const CSV_SYNC_PENDING_JSON_LOCAL = path.join(DAILY_DIR, 'csv-sync-pending.json');
const CSV_SYNC_PENDING_JSON_GITHUB = `${DAILY_JSON_GITHUB_DIR}/csv-sync-pending.json`.replace(/^\/+/, '');
const DAILY_JSON_MIGRATION_CONTROL_PATH = `${DAILY_JSON_GITHUB_DIR}/yearwise-migration-control.json`.replace(/^\/+/, '');
const DAILY_JSON_MIGRATION_LOCK_MS = 10 * 60 * 1000;
let dailyJsonMigrationStatus = { date: '', status: 'idle', startedAt: null, completedAt: null, message: 'Daily JSON synchronization has not run in this process.' };
let dailyJsonMigrationPromise = null;
let dailyJsonMigrationStatusCache = { checkedAt: 0, control: null };

function legacyStableIdentityKey(entity, record) {
  const r = record && typeof record === 'object' ? record : {};
  const first = (...keys) => {
    for (const key of keys) {
      const value = safeString(r[key]).trim();
      if (value) return value;
    }
    return '';
  };
  const date = first('date','entryDate','workDate','attendanceDate','requestDate','startDate','otDate','powerDate','paymentDate','advanceDate','poDate');
  const created = first('createdAt','created_at','createdOn');
  const employee = first('employeeId','workerId','assignedEmployeeId');
  const work = first('workId','workOrderId','jobId','assignmentId','inwardId','inwardItemId','purchaseOrderId','purchaseOrderItemId');
  let fields = [];
  if (entity === 'fl_attendance') fields = [employee, date, first('type','status')];
  else if (entity === 'fl_workorders') fields = [created, date, first('inwardId','inwardItemId','purchaseOrderId','purchaseOrderItemId','customerDcNumber','customerPoNumber')];
  else if (entity === 'fl_invoices') fields = [date, first('documentType','type'), first('number','dcNumber','customerPoNumber','invoiceNumber')];
  else if (entity === 'fl_finance') fields = [date, first('type'), employee, first('amount','salary','advanceAmount'), first('reference','month','salaryPeriod')];
  else if (entity === 'fl_leaves' || entity === 'fl_permissions' || entity === 'fl_sundayot') fields = [employee, date, first('endDate','toDate'), first('type','status'), created];
  else fields = [created, date, employee, work, first('type','number','code')];
  fields = fields.filter(Boolean);
  // Require at least two independent stable attributes (or an immutable
  // creation timestamp plus a date) before attempting a legacy match.
  if (fields.length < 2) return '';
  return `${entity}:${fields.join('|')}`;
}

function deterministicLegacyRecordId(entity, record) {
  const canonical = stableJsonValue ? stableJsonValue(record) : record;
  const digest = crypto.createHash('sha256').update(`${entity}:${JSON.stringify(canonical)}`).digest('hex').slice(0, 24);
  return `legacy_${entity}_${digest}`;
}

// Add IDs only to record-like objects that do not already have one. Existing
// IDs are immutable. Array path + canonical content gives legacy nested rows a
// deterministic first ID, which is then persisted and never regenerated.
function ensureNestedRecordIds(entity, value, parentPath = 'record') {
  if (!value || typeof value !== 'object') return { value, changed:false };
  let changed = false;
  if (Array.isArray(value)) {
    const next = value.map((item, index) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
      const normalized = { ...item };
      if (!recordId(normalized)) {
        const canonical = stableJsonValue ? stableJsonValue(normalized) : normalized;
        const digest = crypto.createHash('sha256').update(`${entity}:${parentPath}:${index}:${JSON.stringify(canonical)}`).digest('hex').slice(0, 24);
        normalized.id = `legacy_${entity}_nested_${digest}`;
        changed = true;
      }
      const nested = ensureNestedRecordIds(entity, normalized, `${parentPath}[${index}]`);
      if (nested.changed) changed = true;
      return nested.value;
    });
    return { value:next, changed };
  }
  const next = { ...value };
  for (const [key, child] of Object.entries(next)) {
    if (Array.isArray(child)) {
      const nested = ensureNestedRecordIds(entity, child, `${parentPath}.${key}`);
      if (nested.changed) { next[key] = nested.value; changed = true; }
    } else if (child && typeof child === 'object') {
      // Recurse through object containers but do not invent IDs for a plain
      // object map (e.g. dailyCompleted); only arrays denote record collections.
      const nested = ensureNestedRecordIds(entity, child, `${parentPath}.${key}`);
      if (nested.changed) { next[key] = nested.value; changed = true; }
    }
  }
  return { value:next, changed };
}

function ensureTopLevelRecordId(entity, record, { legacy = false } = {}) {
  const normalized = { ...record };
  if (!recordId(normalized)) normalized.id = legacy
    ? deterministicLegacyRecordId(entity, normalized)
    : `rec_${crypto.randomUUID()}`;
  const nested = ensureNestedRecordIds(entity, normalized, `record:${recordId(normalized)}`);
  return nested.value;
}

function emptyPendingState() {
  const out = { version: 2, updatedAt: '', entities: {} };
  for (const key of NON_EMPLOYEE_KEYS) out.entities[key] = [];
  return out;
}

function normalizePendingState(value) {
  const src = value && typeof value === 'object' ? value : {};
  const out = emptyPendingState();
  out.updatedAt = safeString(src.updatedAt || src.updated_at).trim();
  const entities = src.entities && typeof src.entities === 'object' ? src.entities : {};
  for (const key of NON_EMPLOYEE_KEYS) {
    out.entities[key] = Array.isArray(entities[key])
      ? entities[key].filter(record => record && typeof record === 'object').map(record => {
          const normalized = { ...record };
          if (!recordId(normalized)) {
            normalized.id = deterministicLegacyRecordId(key, normalized);
            normalized.__legacyIdGenerated = true;
          }
          return normalized;
        })
      : [];
  }
  return out;
}

function mergePendingStates(first, second) {
  const a = normalizePendingState(first);
  const b = normalizePendingState(second);
  const out = emptyPendingState();
  const aTime = Date.parse(safeString(a.updatedAt || '').trim()) || 0;
  const bTime = Date.parse(safeString(b.updatedAt || '').trim()) || 0;
  out.updatedAt = new Date(Math.max(aTime, bTime, Date.now())).toISOString();
  for (const entity of NON_EMPLOYEE_KEYS) {
    const byId = new Map();
    for (const record of a.entities[entity]) {
      const id = recordId(record);
      if (id) byId.set(id, { ...record });
    }
    for (const record of b.entities[entity]) {
      const id = recordId(record);
      if (!id) continue;
      const old = byId.get(id);
      // Never let a stale remote/local snapshot overwrite a newer unsynced
      // record. Both sources are retained by ID and resolved using the
      // record's own update timestamp, with the existing Work Order deep
      // merge preserved.
      if (!old) {
        byId.set(id, { ...record });
      } else {
        const merged = mergeRecordsSafely(entity, old, record);
        // A replacement directive must survive local/remote Pending JSON
        // reconciliation. If either snapshot carries it, keep the merged
        // active list authoritative until that exact list reaches CSV.
        if (entity === 'fl_workorders' && (old.__replaceWorks === true || record.__replaceWorks === true)) {
          const replacementSource = record.__replaceWorks === true ? record : old;
          byId.set(id, {
            ...merged,
            __replaceWorks:true,
            works:(Array.isArray(replacementSource.works) ? replacementSource.works : Array.isArray(merged.works) ? merged.works : []).map(work => ({ ...work }))
          });
        } else {
          byId.set(id, merged);
        }
      }
    }
    out.entities[entity] = [...byId.values()];
  }
  return out;
}

function readDailyJsonFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(decryptText(raw));
  } catch (_) {
    return null;
  }
}

function writeDailyJsonIfChanged(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const encrypted = encryptJsonText(value);
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  if (existing && sameStoredContent(existing, encrypted)) return false;
  const tempFile = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tempFile, encrypted, 'utf8');
  fs.renameSync(tempFile, filePath);
  return true;
}

function readPendingJsonLocal() {
  return normalizePendingState(readDailyJsonFile(PREVIOUS_PENDING_JSON_LOCAL));
}

async function loadPersistentPendingState() {
  const local = fs.existsSync(PREVIOUS_PENDING_JSON_LOCAL) ? readDailyJsonFile(PREVIOUS_PENDING_JSON_LOCAL) : null;
  let merged = normalizePendingState(local);
  if (githubConfig()) {
    try {
      const remote = await githubReadFile(PREVIOUS_PENDING_JSON_GITHUB);
      if (remote?.content) {
        const parsed = JSON.parse(decryptText(remote.content));
        merged = mergePendingStates(merged, parsed);
      }
    } catch (error) {
      console.error('Previous/Pending JSON read failed:', error.message);
      // Keep the verified local buffer if GitHub is temporarily unavailable.
    }
  }
  pendingState = merged;
  pendingStateLoaded = true;
  return normalizePendingState(merged);
}

// Compare JSON values independent of object-property insertion order. JSON
// object key order is not part of the data contract, while array order remains
// significant for record collections and history.
function stableJsonValue(value) {
  if (Array.isArray(value)) return value.map(stableJsonValue);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stableJsonValue(value[key]);
    return out;
  }
  return value;
}
function sameJsonValue(a, b) {
  return JSON.stringify(stableJsonValue(a)) === JSON.stringify(stableJsonValue(b));
}

// CSV synchronization has its own durable journal. Year-wise migration may
// remove verified records from Previous/Pending, but those records remain queued
// here until the monthly/FY CSV files have also been committed and verified.
async function loadPersistentCsvSyncPendingState() {
  if (!githubConfig()) throw new Error('Private GitHub storage is not configured; CSV sync recovery cannot be verified.');
  const local = fs.existsSync(CSV_SYNC_PENDING_JSON_LOCAL) ? readDailyJsonFile(CSV_SYNC_PENDING_JSON_LOCAL) : null;
  const remote = await githubReadFile(CSV_SYNC_PENDING_JSON_GITHUB);
  let remoteState = emptyPendingState();
  if (remote?.content) {
    try { remoteState = normalizePendingState(JSON.parse(decryptText(remote.content))); }
    catch (error) { throw new Error(`Persistent CSV-sync Pending JSON could not be decrypted or parsed: ${error.message}`); }
  }
  const merged = mergePendingStates(normalizePendingState(local), remoteState);
  pendingStateLoaded = true;
  return merged;
}

async function persistCsvSyncPendingState(value) {
  const normalized = normalizePendingState(value);
  normalized.updatedAt = new Date().toISOString();
  try { writeDailyJsonIfChanged(CSV_SYNC_PENDING_JSON_LOCAL, normalized); }
  catch (error) { console.error('Local CSV-sync Pending JSON cache write failed; continuing with GitHub:', error.message); }
  if (!githubConfig()) throw new Error('Permanent GitHub storage is not configured for CSV-sync Pending JSON.');
  const encrypted = encryptJsonText(normalized);
  const saved = await githubWriteFile(CSV_SYNC_PENDING_JSON_GITHUB, encrypted, '[skip render] Update SOV Engineering CSV-sync Pending JSON');
  if (!saved) throw new Error('CSV-sync Pending JSON could not be committed to GitHub.');
  let lastError = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const remote = await githubReadFile(CSV_SYNC_PENDING_JSON_GITHUB);
      if (remote?.content) {
        const parsed = normalizePendingState(JSON.parse(decryptText(remote.content)));
        if (sameJsonValue(parsed, normalized)) {
          try { writeDailyJsonIfChanged(CSV_SYNC_PENDING_JSON_LOCAL, normalized); } catch (_) {}
          return true;
        }
      }
      lastError = new Error('CSV-sync Pending JSON read-back did not match the committed version.');
    } catch (error) { lastError = error; }
    if (attempt < 4) await new Promise(resolve => setTimeout(resolve, 200 * (attempt + 1)));
  }
  throw new Error(`CSV-sync Pending JSON verification failed: ${lastError?.message || 'content mismatch'}`);
}

// GitHub's Contents API can briefly return a previous branch snapshot after a
// successful commit. Serialize pending-JSON commits and retry read-back before
// declaring a genuine verification failure; never skip the verification.
let pendingJsonPersistenceQueue = Promise.resolve();
async function persistPendingState(value = pendingState) {
  const normalized = normalizePendingState(value);
  normalized.updatedAt = new Date().toISOString();
  pendingState = normalized;
  pendingStateLoaded = true;

  // Render Free's local filesystem is not the durable source of truth. Keep a
  // best-effort encrypted local recovery copy, but never let a local disk error
  // prevent the durable GitHub write from being attempted. A failed GitHub write
  // is still returned to the caller as a save failure.
  let localBufferError = null;
  try {
    writeDailyJsonIfChanged(PREVIOUS_PENDING_JSON_LOCAL, normalized);
  } catch (error) {
    localBufferError = error;
    console.error('Local Previous/Pending JSON buffer write failed; continuing with durable GitHub persistence:', error.message);
  }

  const run = pendingJsonPersistenceQueue.then(async () => {
    if (!githubConfig()) throw new Error('Permanent application data storage is not configured. Configure the private GitHub backup before saving application records.');
    const encrypted = encryptJsonText(normalized);
    const saved = await githubWriteFile(
      PREVIOUS_PENDING_JSON_GITHUB,
      encrypted,
      '[skip render] Update SOV Engineering Previous/Pending JSON'
    );
    if (!saved) throw new Error('Previous/Pending JSON persistence failed; the application change must be retried.');

    let lastReadError = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const verified = await githubReadFile(PREVIOUS_PENDING_JSON_GITHUB);
        if (verified?.content) {
          const parsed = normalizePendingState(JSON.parse(decryptText(verified.content)));
          if (sameJsonValue(parsed, normalized)) {
            // Refresh the local cache only after the remote journal has been
            // verified. A local write failure does not invalidate the durable
            // GitHub copy and must not turn a saved change into a false failure.
            try {
              writeDailyJsonIfChanged(PREVIOUS_PENDING_JSON_LOCAL, normalized);
            } catch (error) {
              console.error('GitHub Previous/Pending JSON is verified, but local cache refresh failed:', error.message);
            }
            // Keep a second durable queue for the later CSV sync. Merge by stable
            // record ID so clearing verified year-wise records cannot discard the
            // still-unsynchronized CSV work.
            const csvQueue = await loadPersistentCsvSyncPendingState();
            await persistCsvSyncPendingState(mergePendingStates(csvQueue, normalized));
            return true;
          }
        }
      } catch (error) {
        lastReadError = error;
      }
      if (attempt < 4) await new Promise(resolve => setTimeout(resolve, 200 * (attempt + 1)));
    }
    const detail = lastReadError ? ` (${lastReadError.message})` : '';
    throw new Error('Previous/Pending JSON persistence verification failed after retrying read-back. The operation is not confirmed saved; retry it after checking GitHub connectivity.' + detail);
  });
  pendingJsonPersistenceQueue = run.catch(() => {});
  return run;
}

function emptyDailyState(date) {
  return { version: 1, date, entities: {} };
}

function normalizeDailyState(value, date) {
  const src = value && typeof value === 'object' ? value : {};
  const entities = src.entities && typeof src.entities === 'object' ? src.entities : {};
  const out = emptyDailyState(date);
  for (const key of NON_EMPLOYEE_KEYS) {
    out.entities[key] = Array.isArray(entities[key]) ? entities[key].map(x => ({ ...x })) : [];
  }
  return out;
}

function pendingRecordsForDate(entity, date) {
  if (!pendingStateLoaded) return [];
  return (pendingState.entities?.[entity] || [])
    .filter(record => recordDate(entity, record) === date)
    .map(record => ({ ...record }));
}

async function loadCurrentDailyState(date) {
  const out = buildDailyStateFromCsv(date);
  const pending = await loadPersistentPendingState();
  for (const entity of NON_EMPLOYEE_KEYS) {
    const byId = new Map((out.entities[entity] || []).map(record => [recordId(record), { ...record }]));
    for (const record of pending.entities[entity] || []) {
      if (recordDate(entity, record) !== date) continue;
      const id = recordId(record);
      if (!id) continue;
      const old = byId.get(id);
      const mergedRecord = entity === 'fl_workorders'
        ? mergeEntityRecord(entity, old, record)
        : mergeRecordsSafely(entity, old, record);
      // Preserve the replacement directive in the daily working layer so a
      // subsequent CSV + daily overlay read cannot re-introduce removed Works.
      byId.set(id, entity === 'fl_workorders' && record.__replaceWorks === true
        ? { ...mergedRecord, __replaceWorks:true }
        : mergedRecord);
    }
    out.entities[entity] = [...byId.values()];
  }
  return out;
}

function mergeDailyIntoCsv(date, state) {
  for (const entity of NON_EMPLOYEE_KEYS) {
    const records = Array.isArray(state?.entities?.[entity]) ? state.entities[entity] : [];
    if (!records.length) continue;
    const existing = loadEntityAllFromCsv(entity);
    const byId = new Map(existing.map(r => [recordId(r), { ...r }]));
    for (const incoming of records) {
      const id = recordId(incoming);
      if (!id) continue;
      const old = byId.get(id);
      byId.set(id, entity === 'fl_workorders'
        ? mergeEntityRecord(entity, old, incoming)
        : mergeRecordsSafely(entity, old, incoming));
    }
    writeEntityRecordsToCsv(entity, [...byId.values()]);
  }
}

async function rolloverDailyStateIfNeeded() {
  const today = appTodayStr();
  if (dailyStateLoaded && dailyState.date === today) return;

  try {
    const loaded = await loadCurrentDailyState(today);
    dailyState = normalizeDailyState(loaded, today);
    dailyStateLoaded = true;
  } catch (error) {
    console.error(`Daily state refresh failed for ${today}:`, error.message);
    if (dailyStateLoaded && dailyState?.date === today) return;
    dailyState = emptyDailyState(today);
    dailyStateLoaded = true;
    try { await loadPersistentPendingState(); } catch (_) {}
  }
}

function loadEntityAllFromCsv(entity) {
  const cached = entityAllCsvCache.get(entity);
  if (Array.isArray(cached)) return cached.map(record => ({ ...record }));
  const months = getMonthsForEntity(entity);
  const byId = new Map();
  for (const month of months) {
    for (const record of readEntityMonth(entity, month)) {
      const id = recordId(record);
      if (id) byId.set(id, normalizeIsDeleted({ ...record }));
    }
  }
  const result = [...byId.values()];
  entityAllCsvCache.set(entity, result.map(record => ({ ...record })));
  return result.map(record => ({ ...record }));
}

// ---------------------------------------------------------
// Partitioned encrypted JSON operational store
// ---------------------------------------------------------
// Partition keys are entity/year/month/hash(record ID). Updating a record rewrites
// only the old/new small bucket files, rather than serializing every record or
// parsing CSV during routine requests. The in-memory entity cache accelerates
// existing legacy calculations that still request a full entity array.
function jsonBucketForId(id) {
  const digest = crypto.createHash('sha256').update(safeString(id)).digest();
  return digest.readUInt32BE(0) % JSON_STORE_BUCKETS;
}

function jsonPartitionForRecord(entity, record) {
  const date = recordDate(entity, record);
  const year = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date.slice(0, 4) : appTodayStr().slice(0, 4);
  const month = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date.slice(5, 7) : appTodayStr().slice(5, 7);
  const bucket = String(jsonBucketForId(recordId(record))).padStart(4, '0');
  return path.join(JSON_STORE_ROOT, entity, year, month, `${bucket}.json.enc`);
}

function readJsonPartition(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    const parsed = JSON.parse(decryptText(fs.readFileSync(filePath, 'utf8')));
    const relative = path.relative(JSON_STORE_ROOT, filePath).split(path.sep);
    const entity = relative[0] || 'legacy';
    return Array.isArray(parsed)
      ? parsed.filter(record => record && typeof record === 'object').map(record => {
          const normalized = { ...record };
          // Legacy partitions can predate the current ID requirement. Derive a
          // repeatable ID instead of silently dropping these records; startup
          // reconciliation rewrites and mirrors the normalized partition.
          if (!recordId(normalized)) normalized.id = deterministicLegacyRecordId(entity, normalized);
          return normalizeIsDeleted(normalized);
        })
      : [];
  } catch (error) {
    throw new Error(`Operational JSON partition is unreadable (${path.relative(JSON_STORE_ROOT, filePath)}): ${error.message}`);
  }
}

function listJsonPartitionFiles(entity) {
  const root = path.join(JSON_STORE_ROOT, entity);
  if (!fs.existsSync(root)) return [];
  const out = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && /^\d{4}\.json\.enc$/.test(entry.name)) out.push(full);
    }
  };
  walk(root);
  return out;
}

function listJsonPartitionFilesForMonths(entity, months) {
  const out=[];
  for (const month of new Set((months||[]).filter(value => /^\d{4}-\d{2}$/.test(String(value))))) {
    const dir=path.join(JSON_STORE_ROOT,entity,String(month).slice(0,4),String(month).slice(5,7));
    if(!fs.existsSync(dir)) continue;
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})) {
      if(entry.isFile() && /^\d{4}\.json\.enc$/.test(entry.name)) out.push(path.join(dir,entry.name));
    }
  }
  return out;
}

function writeJsonPartition(filePath, records) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const normalized = records.map(record => normalizeIsDeleted({ ...record })).sort((a, b) => recordId(a).localeCompare(recordId(b), undefined, { numeric: true }));
  const plain = JSON.stringify(normalized);
  if (fs.existsSync(filePath)) {
    try {
      const existing = decryptText(fs.readFileSync(filePath, 'utf8'));
      if (existing === plain) return false;
    } catch (_) { /* Replace an unreadable partition only from the verified in-memory records. */ }
  }
  const temp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temp, encryptText(plain), 'utf8');
  fs.renameSync(temp, filePath);
  return true;
}

const JSON_MIGRATION_ROOT = path.join(JSON_STORE_ROOT, '_migration');
const jsonMigrationStatus = new Map();

function jsonMigrationMarkerPath(entity) {
  return path.join(JSON_MIGRATION_ROOT, `${entity}.json`);
}

function readJsonMigrationMarker(entity) {
  const cached = jsonMigrationStatus.get(entity);
  if (cached?.complete === true) return cached;
  try {
    const marker = JSON.parse(fs.readFileSync(jsonMigrationMarkerPath(entity), 'utf8'));
    if (marker?.version === 1 && marker?.entity === entity && marker?.complete === true) {
      jsonMigrationStatus.set(entity, marker);
      return marker;
    }
  } catch (_) {}
  return null;
}

function writeJsonMigrationMarker(entity, report) {
  fs.mkdirSync(JSON_MIGRATION_ROOT, { recursive: true });
  const marker = { version: 1, entity, complete: true, completedAt: new Date().toISOString(), ...report };
  const target = jsonMigrationMarkerPath(entity);
  const temp = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temp, JSON.stringify(marker, null, 2), 'utf8');
  fs.renameSync(temp, target);
  jsonMigrationStatus.set(entity, marker);
  return marker;
}

function migrateEntityCsvToJsonOnce(entity, existingJsonRecords) {
  // employees.json has a separate, intentionally preserved retrieval and
  // persistence path. Never run this migration for the employee entity.
  if (entity === EMPLOYEE_KEY) return existingJsonRecords;

  // Called only by the explicit Admin migration endpoint. It is idempotent:
  // on interruption, the next attempt merges by existing ID and verifies the
  // result before writing the completion marker. Existing JSON wins conflicts.
  const csvRecords = loadEntityAllFromCsv(entity);
  const byId = new Map();
  for (const record of existingJsonRecords) {
    const id = recordId(record);
    if (id) byId.set(id, { ...record });
  }
  for (const record of csvRecords) {
    const id = recordId(record);
    if (!id) continue;
    const jsonRecord = byId.get(id);
    // Keep the newer version while retaining fields according to the existing
    // entity merge rules; this avoids replacing a newer JSON edit with old CSV.
    byId.set(id, jsonRecord ? mergeRecordsSafely(entity, record, jsonRecord) : { ...record });
  }

  const merged = [...byId.values()];
  entityAllJsonCache.set(entity, existingJsonRecords.map(record => ({ ...record })));
  writeEntityAllToJson(entity, merged);

  // Verify every source ID is now present in JSON before declaring migration
  // complete. CSV files are not modified or deleted by this operation.
  const verified = [];
  for (const file of listJsonPartitionFiles(entity)) verified.push(...readJsonPartition(file));
  const verifiedById = new Map(verified.map(record => [recordId(record), record]));
  const missing = csvRecords.filter(record => !verifiedById.has(recordId(record))).map(recordId);
  if (missing.length) {
    throw new Error(`CSV-to-JSON migration verification failed for ${entity}: ${missing.length} source record(s) are missing.`);
  }
  const existingIds = new Set(existingJsonRecords.map(recordId));
  const report = {
    sourceCsvMonths: getMonthsForEntity(entity).length,
    sourceCsvUniqueRecords: csvRecords.length,
    jsonRecordsBeforeMigration: existingJsonRecords.length,
    jsonRecordsAfterMigration: verifiedById.size,
    processedRecords: csvRecords.length,
    migratedRecords: csvRecords.filter(record => !existingIds.has(recordId(record))).length,
    mergedExistingRecords: csvRecords.filter(record => existingIds.has(recordId(record))).length,
    skippedRecords: csvRecords.filter(record => existingIds.has(recordId(record))).length,
    failedRecords: 0,
    missingSourceRecords: 0
  };
  writeJsonMigrationMarker(entity, report);
  return [...verifiedById.values()];
}

function loadEntityAllFromJson(entity) {
  const cached = entityAllJsonCache.get(entity);
  if (Array.isArray(cached)) return cached.map(record => ({ ...record }));

  const byId = new Map();
  for (const file of listJsonPartitionFiles(entity)) {
    for (const record of readJsonPartition(file)) {
      const id = recordId(record);
      if (id) byId.set(id, record);
    }
  }
  // JSON is the routine source of truth. Never scan CSV or migrate implicitly
  // from a read/login path; CSV recovery is an explicit Admin-only operation.
  const records = [...byId.values()];
  entityAllJsonCache.set(entity, records.map(record => ({ ...record })));
  return records.map(record => ({ ...record }));
}

function writeEntityAllToJson(entity, records, forceAll = false) {
  const nextById = new Map(ensureSoftDeleteField(Array.isArray(records) ? records : [])
    .filter(record => record && typeof record === 'object' && recordId(record))
    .map(record => [recordId(record), { ...record }]));
  const previous = entityAllJsonCache.get(entity);
  let previousById = new Map((previous || []).map(record => [recordId(record), record]));
  if (!previous && !forceAll) {
    // If cache has not been initialized, load the existing partition set without
    // triggering CSV migration; this preserves records when a caller writes early.
    for (const file of listJsonPartitionFiles(entity)) {
      for (const record of readJsonPartition(file)) previousById.set(recordId(record), record);
    }
  }

  const changedIds = new Set();
  for (const [id, oldRecord] of previousById) {
    const next = nextById.get(id);
    if (!next || !sameJsonValue(normalizeIsDeleted(oldRecord), normalizeIsDeleted(next))) changedIds.add(id);
  }
  for (const [id, next] of nextById) {
    const old = previousById.get(id);
    if (!old || !sameJsonValue(normalizeIsDeleted(old), normalizeIsDeleted(next))) changedIds.add(id);
  }

  const touched = new Set();
  for (const id of changedIds) {
    const old = previousById.get(id);
    const next = nextById.get(id);
    if (old) touched.add(jsonPartitionForRecord(entity, old));
    if (next) touched.add(jsonPartitionForRecord(entity, next));
  }
  if (forceAll && !previousById.size) {
    for (const record of nextById.values()) touched.add(jsonPartitionForRecord(entity, record));
  }

  for (const file of touched) {
    const affectedIds = new Set([...changedIds].filter(id => {
      const old = previousById.get(id);
      const next = nextById.get(id);
      return (old && jsonPartitionForRecord(entity, old) === file) || (next && jsonPartitionForRecord(entity, next) === file);
    }));
    const existingRows = fs.existsSync(file) ? readJsonPartition(file) : [];
    const byId = new Map(existingRows.filter(record => !affectedIds.has(recordId(record))).map(record => [recordId(record), record]));
    for (const id of affectedIds) {
      const next = nextById.get(id);
      if (next && jsonPartitionForRecord(entity, next) === file) byId.set(id, { ...next });
    }
    // Keep empty encrypted partitions as tombstone-free empty arrays. They are
    // small and avoid risky file deletion during cross-month edits.
    writeJsonPartition(file, [...byId.values()]);
  }

  entityAllJsonCache.set(entity, [...nextById.values()].map(record => ({ ...record })));
  return {
    changed: changedIds.size,
    count: nextById.size,
    partitions: touched.size,
    changedFiles: [...touched]
  };
}

function dailyOverlayRecords(entity, baseRecords) {
  const byId = new Map((baseRecords || []).map(r => [recordId(r), { ...r }]));

  // The date-specific working layer is kept for the existing daily behavior.
  // It must never be the only unsynchronized overlay, however: Previous/Pending
  // JSON is the durable source for every change that has not yet reached CSV.
  const daily = Array.isArray(dailyState?.entities?.[entity]) ? dailyState.entities[entity] : [];
  for (const incoming of daily) {
    const id = recordId(incoming);
    if (!id) continue;
    const old = byId.get(id);
    byId.set(id, entity === 'fl_workorders'
      ? mergeEntityRecord(entity, old, incoming)
      : mergeRecordsSafely(entity, old, incoming));
  }

  // After restart/redeploy, dailyState is intentionally rebuilt for today.
  // Overlay the complete date-independent Previous/Pending buffer as well so
  // unsynced records from older dates/months remain visible and editable.
  // This does not write anything to CSV and therefore does not change the
  // existing deferred-synchronization model.
  const pending = pendingStateLoaded
    ? pendingState
    : readPendingJsonLocal();
  const pendingRecords = Array.isArray(pending?.entities?.[entity])
    ? pending.entities[entity]
    : [];
  for (const incoming of pendingRecords) {
    const id = recordId(incoming);
    if (!id) continue;
    const old = byId.get(id);
    byId.set(id, entity === 'fl_workorders'
      ? mergeEntityRecord(entity, old, incoming)
      : mergeRecordsSafely(entity, old, incoming));
  }

  return [...byId.values()];
}

async function persistDailyState() {
  // The single Previous/Pending JSON is the durable synchronization buffer.
  // It is date-independent and never gets cleared during date rollover.
  if (!dailyStateLoaded || !dailyState?.date) return false;
  if (!pendingStateLoaded) await loadPersistentPendingState();
  return persistPendingState(pendingState);
}

async function syncCsvFilesToGitHubForEntities(state) {
  for (const entity of NON_EMPLOYEE_KEYS) {
    if (Array.isArray(state?.entities?.[entity]) && state.entities[entity].length) {
      await syncCsvFilesToGitHub(entity, loadEntityAllFromCsv(entity));
    }
  }
}

/* ---------------------------------------------------------
 * Read/write entity data
 * --------------------------------------------------------- */

function loadEntityAll(
  entity
) {
  return dailyOverlayRecords(entity, loadEntityAllFromJson(entity));
}

// ID-targeted read for routine mutations. The cache is initialized by startup
// recovery in the GitHub-backed deployment; only a cold/local-only process has
// to build the entity cache once. Merge only the matching Pending/Daily rows.
function loadEntityRecordById(entity, id) {
  const targetId = safeString(id).trim();
  if (!targetId) return null;
  const base = loadEntityAllFromJson(entity).find(record => recordId(record) === targetId);
  let current = base ? { ...base } : null;
  const localPending = pendingStateLoaded ? pendingState : readPendingJsonLocal();
  const overlays = [
    Array.isArray(dailyState?.entities?.[entity]) ? dailyState.entities[entity] : [],
    Array.isArray(localPending?.entities?.[entity]) ? localPending.entities[entity] : []
  ];
  for (const rows of overlays) {
    const incoming = rows.find(record => recordId(record) === targetId);
    if (!incoming) continue;
    current = current
      ? (entity === 'fl_workorders' ? mergeEntityRecord(entity, current, incoming) : mergeRecordsSafely(entity, current, incoming))
      : { ...incoming };
  }
  return current;
}

function readEntityMonth(
  entity,
  month
) {
  const file =
    monthlyFile(month);

  return entityRowsFromFile(
    file,
    entity
  ).map(
    item => item.record
  );
}

function readEntityFinancialYear(
  entity,
  fy
) {
  const file =
    financialYearFile(fy);

  return entityRowsFromFile(
    file,
    entity
  ).map(
    item => item.record
  );
}

/*
 * IMPORTANT:
 * This function NEVER physically removes an old record
 * because it is missing from the incoming active array.
 *
 * Existing records are merged with incoming records.
 * A record is only marked deleted when the incoming record
 * explicitly contains isDeleted=true.
 */
function writeEntityRecordsToCsv(
  entity,
  records
) {
  ensureCsvDirs();
  let changed = false;
  const changedMonths = new Set();

  const incoming = ensureSoftDeleteField(Array.isArray(records) ? records : [])
    .filter(record => record && typeof record === 'object')
    .map(record => ensureTopLevelRecordId(entity, record));

  // CSV itself is the historical baseline for this durable transaction. Do
  // not let the current Temp JSON accidentally replace or delete history.
  const existing = loadEntityAllFromCsv(entity);
  const merged = new Map(existing.map(record => [recordId(record), normalizeIsDeleted({ ...record })]));
  for (const record of incoming) {
    const id = recordId(record);
    const old = merged.get(id);
    // Pending JSON can be older than a newer CSV version when requests overlap
    // or a retry follows a partial write. Use the same timestamp-aware merge
    // policy as the read/sync layers instead of blindly letting the incoming
    // snapshot overwrite newer persisted fields.
    merged.set(id, mergeRecordsSafely(entity, old, record));
  }

  const finalRecords = [...merged.values()].map(record => {
    const clean = normalizeIsDeleted({ ...record });
    // __replaceWorks is a transient Previous/Pending JSON merge directive. It
    // must never be written into encrypted CSV payloads or exposed as record data.
    delete clean.__replaceWorks;
    return clean;
  });
  const existingRowsById = new Map();
  for (const month of getMonthsForEntity(entity)) {
    for (const row of entityRowsFromFile(monthlyFile(month), entity)) {
      if (row.id) existingRowsById.set(row.id, row);
    }
  }

  const months = new Set(finalRecords.map(record => monthFor(recordDate(entity, record))));
  for (const month of getMonthsForEntity(entity)) months.add(month);

  for (const month of months) {
    const file = monthlyFile(month);
    const allRows = readCsvFile(file);
    const otherEntityRows = allRows.filter(row => row.entity !== entity);
    const monthRecords = finalRecords.filter(record => monthFor(recordDate(entity, record)) === month);
    const entityRows = monthRecords.map(record => {
      const previous = existingRowsById.get(recordId(record));
      const payload = json(normalizeIsDeleted({ ...record }));
      return {
        entity,
        id: recordId(record),
        date: recordDate(entity, record),
        financial_year: fyFor(recordDate(entity, record)),
        // Preserve the existing CSV metadata when the record payload is
        // unchanged. This prevents a no-op Admin login from changing CSV.
        updated_at: previous && safeString(previous.payload) === payload
          ? previous.updated_at
          : safeString(record.updatedAt || record.updated_at || record.createdAt || record.created_at || previous?.updated_at || new Date().toISOString()),
        payload
      };
    });
    const monthChanged = writeCsvFile(file, CSV_HEADERS, [...otherEntityRows, ...entityRows]);
    if (monthChanged) {
      changed = true;
      changedMonths.add(month);
    }
  }

  if (updateIndexForEntity(entity, finalRecords)) changed = true;
  invalidateEntityCsvCache(entity);
  return {
    changed,
    changedMonths: [...changedMonths],
    count: finalRecords.length,
    activeCount: finalRecords.filter(activeRecord).length,
    deletedCount: finalRecords.filter(isDeleted).length
  };
}

function mergeIncomingAgainstLatest(entity, latest, incoming) {
  const latestMap = new Map((latest || []).map(record => [recordId(record), record]));
  const out = [];
  for (const record of ensureSoftDeleteField(Array.isArray(incoming) ? incoming : [])) {
    const id = recordId(record);
    if (!id) continue;
    const old = latestMap.get(id);
    out.push(entity === 'fl_workorders'
      ? mergeEntityRecord(entity, old, record)
      : mergeRecordsSafely(entity, old, record));
  }
  return out;
}

async function writeEntityRecordsUnsafe(entity, records) {
  ensureCsvDirs();
  const incoming = ensureSoftDeleteField(Array.isArray(records) ? records : [])
    .filter(record => record && typeof record === 'object' && recordId(record))
    .map(record => ({ ...record }));
  if (!dailyStateLoaded) throw new Error('Daily data store is not ready.');
  if (!pendingStateLoaded) await loadPersistentPendingState();

  const today = appTodayStr();
  const jsonBase = new Map(loadEntityAllFromJson(entity).map(record => [recordId(record), { ...record }]));
  const current = new Map(loadEntityAll(entity).map(record => [recordId(record), { ...record }]));

  for (const record of incoming) {
    const id = recordId(record);
    const oldCurrent = current.get(id);
    const merged = entity === 'fl_workorders'
      ? mergeEntityRecord(entity, oldCurrent, record)
      : mergeRecordsSafely(entity, oldCurrent, record);
    current.set(id, merged);

    const csvRecord = jsonBase.get(id);
    const pendingRecord = (pendingState.entities[entity] || []).find(item => recordId(item) === id);
    const baseline = pendingRecord || csvRecord;
    const changed = JSON.stringify(normalizeIsDeleted(merged)) !== JSON.stringify(normalizeIsDeleted(baseline || {}));
    const isCurrentDay = recordDate(entity, record) === today || safeString(record.updatedAt).slice(0, 10) === today || safeString(record.createdAt).slice(0, 10) === today;

    // The single Previous/Pending JSON retains every changed record until
    // CSV synchronization has completed and been verified. Current-day data
    // continues to use the same working behavior as before, but it is now
    // stored in the date-independent pending buffer.
    if (changed || isCurrentDay) {
      const list = pendingState.entities[entity] || [];
      const byId = new Map(list.map(item => [recordId(item), { ...item }]));
      const oldPending = byId.get(id);
      byId.set(id, oldPending
        ? (record.__replaceWorks === true
            ? { ...mergeRecordsSafely(entity, oldPending, { ...merged, __replaceWorks:true }), __replaceWorks:true, works: (Array.isArray(merged.works) ? merged.works : []).map(work => ({ ...work })) }
            : mergeRecordsSafely(entity, oldPending, merged))
        : { ...merged, ...(record.__replaceWorks === true ? { __replaceWorks:true } : {}) });
      pendingState.entities[entity] = [...byId.values()];
    }

    // Keep the explicit replacement directive on the in-memory daily overlay
    // until it has been merged with the CSV baseline. mergeEntityRecord strips
    // the directive from its output, so add it back only for this stored layer.
    if (entity === 'fl_workorders') {
      const latestRecord = current.get(id);
      if (latestRecord && record.__replaceWorks === true) current.set(id, { ...latestRecord, __replaceWorks:true });
    }
    dailyState.entities[entity] = [...current.values()];
  }

  // Write-ahead order is intentional: commit the complete Previous/Pending
  // recovery snapshot to GitHub and verify it BEFORE updating the disposable
  // Render-local operational JSON partitions. If the process stops at any point
  // after this await, startup can rebuild the partitions from the durable buffer.
  // Pending remains retained until CSV synchronization is separately verified.
  await persistPendingState(pendingState);
  const jsonWrite = writeEntityAllToJson(entity, [...current.values()]);
  const jsonFilesToSync = new Set(jsonWrite.changedFiles || []);
  for (const record of incoming) {
    const id = recordId(record);
    const latest = current.get(id) || record;
    jsonFilesToSync.add(jsonPartitionForRecord(entity, latest));
  }
  await syncOperationalJsonPartitionsToGitHub(entity, [...jsonFilesToSync]);
  broadcastDataUpdated(entity, incoming.map(record => recordId(record)).filter(Boolean));

  const finalRecords = [...current.values()].map(normalizeIsDeleted);
  const committedRecords = incoming.map(record => current.get(recordId(record))).filter(Boolean).map(normalizeIsDeleted);
  return { count: finalRecords.length, activeCount: finalRecords.filter(activeRecord).length, deletedCount: finalRecords.filter(isDeleted).length, records: finalRecords, committedRecords };
}

async function writeEntityRecords(entity, records) {
  while (jsonMigrationCommitInProgress) await (jsonMigrationCommitWaiter || Promise.resolve());
  // Normal writes and explicit CSV synchronization must share the same queue.
  // Otherwise a CSV sync can read Pending JSON, a newer write can update it,
  // and the sync can later persist its older snapshot and erase that change.
  const run = durableCsvWriteQueue.then(() => writeEntityRecordsUnsafe(entity, records));
  durableCsvWriteQueue = run.catch(() => {});
  return run;
}

function readAllEntityRecords(
  entity
) {
  return loadEntityAll(
    entity
  );
}

/* ---------------------------------------------------------
 * Filter records
 * --------------------------------------------------------- */

function dateRangeExceedsMaxMonths(from, to) {
  if (!from || !to) return false;
  const start = new Date(`${safeString(from).slice(0,10)}T00:00:00Z`);
  const end = new Date(`${safeString(to).slice(0,10)}T00:00:00Z`);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end < start) return false;
  const months = (end.getUTCFullYear() - start.getUTCFullYear()) * 12 + (end.getUTCMonth() - start.getUTCMonth());
  return months > MAX_DATE_RANGE_MONTHS || (months === MAX_DATE_RANGE_MONTHS && end.getUTCDate() > start.getUTCDate());
}

function datesCoveredByFilters(filters = {}) {
  const out = [];
  if (filters.date && /^\d{4}-\d{2}-\d{2}$/.test(String(filters.date))) return [String(filters.date)];
  if (filters.from || filters.to) {
    const start = String(filters.from || filters.to).slice(0,10);
    const end = String(filters.to || filters.from).slice(0,10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) return out;
    if (dateRangeExceedsMaxMonths(start, end)) return out;
    let cursor = new Date(`${start}T00:00:00Z`);
    const last = new Date(`${end}T00:00:00Z`);
    while (cursor <= last) {
      out.push(cursor.toISOString().slice(0,10));
      cursor.setUTCDate(cursor.getUTCDate()+1);
    }
    return out;
  }
  if (filters.month && /^\d{4}-\d{2}$/.test(String(filters.month))) {
    const start = new Date(`${filters.month}-01T00:00:00Z`);
    const year = start.getUTCFullYear(), month = start.getUTCMonth();
    const last = new Date(Date.UTC(year, month+1, 0));
    for (let d=1; d<=last.getUTCDate(); d++) out.push(`${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`);
  }
  return out;
}

function mergeOriginalDailyJsonIntoRecords(entity, records, filters = {}) {
  const dates = datesCoveredByFilters(filters);
  if (!dates.length) return records;
  const wantedDates = new Set(dates);
  const pending = pendingStateLoaded ? normalizePendingState(pendingState) : readPendingJsonLocal();
  const byId = new Map((records || []).map(r => [recordId(r), { ...r }]));
  const incoming = Array.isArray(pending.entities?.[entity]) ? pending.entities[entity] : [];
  for (const record of incoming) {
    const date = recordDate(entity, record);
    if (!wantedDates.has(date)) continue;
    const id = recordId(record);
    if (!id) continue;
    const old = byId.get(id);
    byId.set(id, mergeRecordsSafely(entity, old, record));
  }
  return [...byId.values()];
}

function monthRangeForFilters(filters = {}) {
  const months = new Set();
  const addMonth = value => {
    const m = monthFor(value);
    if (/^\d{4}-\d{2}$/.test(m)) months.add(m);
  };

  if (filters.date) addMonth(filters.date);
  if (filters.month && /^\d{4}-\d{2}$/.test(String(filters.month))) addMonth(filters.month);

  if (filters.from || filters.to) {
    const start = String(filters.from || filters.to).slice(0, 10);
    const end = String(filters.to || filters.from).slice(0, 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(start) && /^\d{4}-\d{2}-\d{2}$/.test(end)) {
      let cursor = new Date(`${start.slice(0,7)}-01T00:00:00Z`);
      const last = new Date(`${end.slice(0,7)}-01T00:00:00Z`);
      while (cursor <= last && months.size < 120) {
        months.add(cursor.toISOString().slice(0, 7));
        cursor.setUTCMonth(cursor.getUTCMonth() + 1);
      }
    }
  }

  if (filters.financialYear && /^\d{4}-\d{4}$/.test(String(filters.financialYear))) {
    const startYear = Number(String(filters.financialYear).slice(0, 4));
    for (let month = 4; month <= 12; month++) months.add(`${startYear}-${String(month).padStart(2,'0')}`);
    for (let month = 1; month <= 3; month++) months.add(`${startYear + 1}-${String(month).padStart(2,'0')}`);
  }

  return [...months];
}

function loadCurrentDayEntityRecords(entity) {
  const todayMonth = monthFor(appTodayStr());
  const byId = new Map();
  for (const file of listJsonPartitionFilesForMonths(entity, [todayMonth])) for (const record of readJsonPartition(file)) {
    const id = recordId(record);
    if (id) byId.set(id, normalizeIsDeleted({ ...record }));
  }

  // The daily JSON working layer may contain a historical Work Order master
  // record whose nested work activity was updated today. Merge that overlay
  // without filtering on the master's own date.
  const daily = Array.isArray(dailyState?.entities?.[entity]) ? dailyState.entities[entity] : [];
  for (const incoming of daily) {
    const id = recordId(incoming);
    if (!id) continue;
    const old = byId.get(id);
    byId.set(id, entity === 'fl_workorders'
      ? mergeEntityRecord(entity, old, incoming)
      : mergeRecordsSafely(entity, old, incoming));
  }
  return [...byId.values()];
}

function loadEntityRecordsForFilter(entity, filters = {}) {
  const months = monthRangeForFilters(filters);
  if (!months.length) return readAllEntityRecords(entity);

  const byId = new Map();
  for (const file of listJsonPartitionFilesForMonths(entity, months)) {
    for (const record of readJsonPartition(file)) {
      const id = recordId(record);
      if (id) byId.set(id, normalizeIsDeleted({ ...record }));
    }
  }

  // The single Previous/Pending JSON is merged before the current working
  // layer so unsynchronized historical records remain visible to filtered reads.
  const originalMerged = mergeOriginalDailyJsonIntoRecords(entity, [...byId.values()], filters);
  byId.clear();
  for (const record of originalMerged) byId.set(recordId(record), record);

  // Temp JSON is the current working overlay. Merge it only for the requested
  // date range so historical queries do not repeatedly load unrelated data.
  const daily = Array.isArray(dailyState?.entities?.[entity]) ? dailyState.entities[entity] : [];
  for (const incoming of daily) {
    const id = recordId(incoming);
    if (!id) continue;
    const d = recordDate(entity, incoming);
    const start = safeString(filters.from || '').slice(0, 10);
    const end = safeString(filters.to || '').slice(0, 10);
    if (filters.date && d !== safeString(filters.date).slice(0, 10)) continue;
    if (start && d < start) continue;
    if (end && d > end) continue;
    if (filters.month && monthFor(d) !== safeString(filters.month)) continue;
    if (filters.financialYear && fyFor(d) !== safeString(filters.financialYear)) continue;
    const old = byId.get(id);
    byId.set(id, entity === 'fl_workorders'
      ? mergeEntityRecord(entity, old, incoming)
      : mergeRecordsSafely(entity, old, incoming));
  }
  return [...byId.values()];
}

function loadEntityByFilter(
  entity,
  filters = {}
) {
  let records =
    loadEntityRecordsForFilter(
      entity,
      filters
    );

  const employeeFilter =
    safeString(
      filters.employeeId
    ).trim();

  records =
    records.filter(
      record =>
        !isDeleted(record)
    );

  if (
    filters.date
  ) {
    records =
      records.filter(
        record =>
          recordDate(
            entity,
            record
          ) ===
          safeString(
            filters.date
          )
      );
  }

  if (
    filters.from
  ) {
    records =
      records.filter(
        record =>
          recordDate(
            entity,
            record
          ) >=
          safeString(
            filters.from
          )
      );
  }

  if (
    filters.to
  ) {
    records =
      records.filter(
        record =>
          recordDate(
            entity,
            record
          ) <=
          safeString(
            filters.to
          )
      );
  }

  if (
    filters.month
  ) {
    records =
      records.filter(
        record =>
          monthFor(
            recordDate(
              entity,
              record
            )
          ) ===
          safeString(
            filters.month
          )
      );
  }

  if (
    filters.financialYear
  ) {
    records =
      records.filter(
        record =>
          fyFor(
            recordDate(
              entity,
              record
            )
          ) ===
          safeString(
            filters.financialYear
          )
      );
  }

  if (
    employeeFilter
  ) {
    records =
      records.filter(
        record => {
          const employeeId =
            safeString(
              record.employeeId
            ).trim();

          const workerId =
            safeString(
              record.workerId
            ).trim();

          const assignedIds =
            Array.isArray(
              record.assignedTo
            )
              ? record.assignedTo
                  .map(
                    employeeIdFromReference
                  )
              : record.assignedTo
                ? [
                    employeeIdFromReference(
                      record.assignedTo
                    )
                  ]
                : [];

          return (
            employeeId ===
              employeeFilter ||
            workerId ===
              employeeFilter ||
            assignedIds.includes(
              employeeFilter
            )
          );
        }
      );
  }

  return records;
}

/* ---------------------------------------------------------
 * GitHub CSV persistence
 * --------------------------------------------------------- */

function githubConfig() {
  const token =
    safeString(
      process.env.GITHUB_TOKEN
    ).trim();

  let repo =
    safeString(
      process.env.GITHUB_REPO
    ).trim();

  const owner =
    safeString(
      process.env.GITHUB_OWNER
    ).trim();

  /* Support both deployment styles:
     GITHUB_REPO=owner/repository
     or GITHUB_OWNER=owner + GITHUB_REPO=repository */
  if (owner && repo && !repo.includes('/')) {
    repo = `${owner}/${repo}`;
  }

  const branch =
    safeString(
      process.env.GITHUB_BRANCH ||
      'main'
    ).trim();

  const basePath =
    safeString(
      process.env.GITHUB_CSV_PATH ||
      'data/csv'
    )
      .replace(/^\/+|\/+$/g, '');

  if (
    !token ||
    !repo
  ) {
    return null;
  }

  return {
    token,
    repo,
    branch,
    basePath
  };
}

// Operational GitHub JSON accepts a 32-byte hex key or a 16+ byte text
// passphrase. Text passphrases use scrypt with a per-document random salt.
const businessDerivedKeyCache = new Map();
function businessEncryptionKeys() {
  const currentRaw = safeString(process.env.DATA_ENCRYPTION_KEY).trim();
  const values = [currentRaw, ...safeString(process.env.DATA_ENCRYPTION_PREVIOUS_KEYS).split(',').map(v => v.trim()).filter(Boolean)];
  const keys = values.map(raw => {
    const isHexKey = /^[a-f0-9]{64}$/i.test(raw);
    const material = isHexKey ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'utf8');
    if (!isHexKey && material.length < 16) throw new Error('DATA_ENCRYPTION_KEY must be a 64-character hex key or a text passphrase of at least 16 bytes.');
    if (material.length > 1024) throw new Error('DATA_ENCRYPTION_KEY is too long.');
    return { material, kdf: isHexKey ? 'raw-hex-v1' : 'scrypt-v1', keyId: crypto.createHash('sha256').update(material).digest('hex').slice(0, 16) };
  });
  if (!currentRaw) throw new Error('DATA_ENCRYPTION_KEY is not configured. Set a 64-character hex key or a text passphrase of at least 16 bytes.');
  if (new Set(keys.map(item => item.keyId)).size !== keys.length) throw new Error('DATA_ENCRYPTION_KEY and previous keys must be unique.');
  return keys;
}

function deriveBusinessDataKey(entry, salt, kdf = entry.kdf) {
  if (kdf === 'raw-hex-v1') {
    if (entry.material.length !== 32) throw new Error('The configured key cannot read this encrypted document.');
    return entry.material;
  }
  if (kdf !== 'scrypt-v1' || salt.length !== 16) throw new Error('Unsupported business-data key derivation format.');
  const cacheId = entry.keyId + ':' + salt.toString('hex');
  if (businessDerivedKeyCache.has(cacheId)) {
    const cached = businessDerivedKeyCache.get(cacheId);
    businessDerivedKeyCache.delete(cacheId); businessDerivedKeyCache.set(cacheId, cached);
    return cached;
  }
  const derived = crypto.scryptSync(entry.material, salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  businessDerivedKeyCache.set(cacheId, derived);
  if (businessDerivedKeyCache.size > 64) businessDerivedKeyCache.delete(businessDerivedKeyCache.keys().next().value);
  return derived;
}

function encryptBusinessJson(value) {
  const [entry] = businessEncryptionKeys();
  const iv = crypto.randomBytes(12);
  const salt = crypto.randomBytes(16);
  const key = deriveBusinessDataKey(entry, salt);
  const metadata = { format: 'sov-business-json', version: 2, algorithm: 'aes-256-gcm', keyId: entry.keyId, kdf: entry.kdf, kdfSalt: salt.toString('base64') };
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(metadata), 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value, null, 2) + '\n', 'utf8'), cipher.final()]);
  return JSON.stringify({ ...metadata,
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }, null, 2) + '\n';
}

function decryptBusinessJson(storedText, label) {
  let envelope;
  try { envelope = JSON.parse(String(storedText || '')); }
  catch (_) { throw new Error('Invalid encrypted JSON in ' + label + '; original GitHub file preserved.'); }
  if (!envelope || envelope.format !== 'sov-business-json' || ![1, 2].includes(envelope.version) || envelope.algorithm !== 'aes-256-gcm' ||
      !envelope.keyId || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
    throw new Error(label + ' is not in the supported encrypted format; original GitHub file preserved. Plaintext is not accepted.');
  }
  const keys = businessEncryptionKeys();
  const selected = keys.find(item => item.keyId === envelope.keyId);
  if (!selected) throw new Error('No configured data-encryption key can read ' + label + '; preserve the file and configure its key.');
  try {
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    if (iv.length !== 12 || tag.length !== 16 || !ciphertext.length) throw new Error('Invalid encrypted payload dimensions.');
    const kdf = envelope.version === 1 ? 'raw-hex-v1' : envelope.kdf;
    const salt = envelope.version === 1 ? Buffer.alloc(16) : Buffer.from(envelope.kdfSalt || '', 'base64');
    const key = deriveBusinessDataKey(selected, salt, kdf);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    if (envelope.version === 2) {
      const metadata = { format: envelope.format, version: envelope.version, algorithm: envelope.algorithm, keyId: envelope.keyId, kdf: envelope.kdf, kdfSalt: envelope.kdfSalt };
      decipher.setAAD(Buffer.from(JSON.stringify(metadata), 'utf8'));
    }
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    return JSON.parse(plain);
  } catch (_) {
    throw new Error('Encrypted data verification failed for ' + label + '; the file may be corrupted or tampered with. Original file preserved.');
  }
}

async function githubFetchWithTimeout(url, options = {}, timeoutMs = 12000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref?.();
  try {
    return await fetch(url, { ...options, signal: options.signal || controller.signal });
  } catch (error) {
    if (controller.signal.aborted) throw new Error(`GitHub request timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function githubRequest(
  filePath,
  options = {}
) {
  const config =
    githubConfig();

  if (!config) {
    return null;
  }

  const api =
    `https://api.github.com/repos/${config.repo}/contents/${filePath}`;

  const requestOptions = { ...options };
  const accept = safeString(requestOptions.accept).trim() || 'application/vnd.github+json';
  delete requestOptions.accept;

  const headers = {
    Authorization:
      `Bearer ${config.token}`,

    Accept: accept,

    'X-GitHub-Api-Version':
      '2022-11-28',

    'User-Agent':
      'sov-engineering-app',

    ...(requestOptions.body
      ? {
          'Content-Type':
            'application/json'
        }
      : {})
  };

  return fetch(
    api,
    {
      ...requestOptions,
      headers
    }
  );
}

async function githubReadFile(
  relativePath
) {
  const config =
    githubConfig();

  if (!config) {
    return null;
  }

  const apiPath = `${config.basePath}/${relativePath}?ref=${encodeURIComponent(config.branch)}`;
  const response = await githubRequest(apiPath);

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    throw new Error(`GitHub CSV read failed: ${response.status}${detail ? ` ${detail}` : ''}`);
  }

  const body = await response.json();

  // GitHub's Contents API may omit `content` (encoding="none") for files
  // larger than its normal inline-content limit. Previously that case was
  // treated as an empty file, which made a successful monthly CSV write fail
  // read-back verification for larger months. Retry the same authenticated,
  // branch-pinned path with GitHub's raw media type instead of comparing an
  // empty string. Keep the SHA from the JSON response for subsequent PUTs.
  let content = '';
  if (body.content && body.encoding === 'base64') {
    content = Buffer.from(body.content, 'base64').toString('utf8');
  } else if (body.download_url || body.encoding === 'none' || !body.content) {
    const rawResponse = await githubRequest(apiPath, { accept: 'application/vnd.github.raw+json' });
    if (!rawResponse.ok) {
      const detail = (await rawResponse.text()).slice(0, 300);
      throw new Error(`GitHub raw CSV read failed: ${rawResponse.status}${detail ? ` ${detail}` : ''}`);
    }
    content = await rawResponse.text();
  }

  return {
    content,
    sha: body.sha || null
  };
}

async function githubDeleteFileIfExists(relativePath, message) {
  const config = githubConfig();
  if (!config) return false;
  const current = await githubReadFile(relativePath);
  if (!current?.sha) return false;
  const response = await githubRequest(`${config.basePath}/${relativePath}`, {
    method: 'DELETE',
    body: JSON.stringify({ message, sha: current.sha, branch: config.branch })
  });
  if (!response.ok && response.status !== 404) throw new Error(`GitHub daily file delete failed: ${response.status}`);
  return true;
}

async function githubWriteFile(
  relativePath,
  content,
  message,
  options = {}
) {
  const config =
    githubConfig();

  if (!config) {
    return false;
  }

  const current =
    await githubReadFile(
      relativePath
    );

  // GitHub's Contents API creates a commit for a PUT. Never issue that PUT
  // when the stored plaintext is unchanged; encrypted content may differ only
  // because AES-GCM generated a new random IV.
  if (current?.content != null && sameStoredContent(current.content, content)) {
    // This read already verified the exact stored content; allow CSV sync to
    // reuse it instead of making a duplicate read-only network request.
    return options.returnDetails ? { ok:true, unchanged:true, content:current.content } : true;
  }

  const body = {
    // Operational data commits must never trigger the application's Render
    // source deployment. Render supports this explicit skip marker.
    message: `${message} [skip render]`,

    content:
      Buffer.from(
        content,
        'utf8'
      ).toString('base64'),

    branch:
      config.branch
  };

  if (
    current?.sha
  ) {
    body.sha =
      current.sha;
  }

  const response =
    await githubRequest(
      `${config.basePath}/${relativePath}`,
      {
        method: 'PUT',
        body:
          JSON.stringify(body)
      }
    );

  if (!response.ok) {
    const text =
      await response.text();

    throw new Error(
      `GitHub CSV write failed: ${response.status} ${text.slice(0, 300)}`
    );
  }

  return options.returnDetails ? { ok:true, unchanged:false, content:null } : true;
}

// Root-level repository operations are used only by the explicit backup workflow.
// Unlike githubReadFile/githubWriteFile, these helpers intentionally do not prepend
// GITHUB_CSV_PATH because the required destination is the repository-root backup/.
async function githubRepositoryRequest(repositoryPath, options = {}) {
  const config = githubConfig();
  if (!config) return null;
  const safePath = String(repositoryPath || '').replace(/^\/+/, '');
  const requestOptions = { ...options };
  const method = String(requestOptions.method || 'GET').toUpperCase();
  // All backup reads and preflight SHA lookups must target the same branch as
  // Contents API writes. Without ?ref=<configured branch>, GitHub reads the
  // default branch, causing false verification failures when GITHUB_BRANCH
  // differs from the repository's default branch.
  const url = new URL(`https://api.github.com/repos/${config.repo}/contents/${safePath}`);
  if (method === 'GET' && !url.searchParams.has('ref')) {
    url.searchParams.set('ref', config.branch || 'main');
  }
  const accept = safeString(requestOptions.accept).trim() || 'application/vnd.github+json';
  delete requestOptions.accept;
  const headers = {
    Authorization: `Bearer ${config.token}`,
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'sov-engineering-app',
    ...(requestOptions.body ? { 'Content-Type': 'application/json' } : {})
  };
  return githubFetchWithTimeout(url.toString(), { ...requestOptions, headers });
}

function comparableGitHubText(text) {
  // Compare JSON semantically to avoid false mismatches from serialization or
  // trailing newline differences. Non-JSON files use normalized line endings.
  try { return JSON.stringify(JSON.parse(String(text))); }
  catch (_) { return String(text).replace(/\r\n/g, '\n').replace(/\n+$/, ''); }
}

async function githubReadRepositoryText(repositoryPath) {
  const response = await githubRepositoryRequest(repositoryPath);
  if (!response) throw new Error('GitHub backup is not configured.');
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`GitHub backup read failed for ${repositoryPath}: ${response.status} ${(await response.text()).slice(0,240)}`);
  const body = await response.json();
  if (body.encoding === 'base64' && body.content) return Buffer.from(body.content.replace(/\s/g, ''), 'base64').toString('utf8');
  const raw = await githubRepositoryRequest(repositoryPath, { accept:'application/vnd.github.raw+json' });
  if (!raw.ok) throw new Error(`GitHub backup raw read failed for ${repositoryPath}: ${raw.status} ${(await raw.text()).slice(0,240)}`);
  return await raw.text();
}

async function githubCreateRepositoryTextImmutable(repositoryPath, content, message) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub backup is not configured.');
  const metadata = await githubRepositoryRequest(repositoryPath);
  if (metadata?.ok) throw new Error(`Immutable backup already exists and will not be overwritten: ${repositoryPath}`);
  if (metadata && metadata.status !== 404) throw new Error(`GitHub backup preflight failed for ${repositoryPath}: ${metadata.status} ${(await metadata.text()).slice(0,240)}`);
  const body = { message:`${message} [skip render]`, content:Buffer.from(content,'utf8').toString('base64'), branch:config.branch };
  const put = await githubRepositoryRequest(repositoryPath, {method:'PUT', body:JSON.stringify(body)});
  if (!put.ok) throw new Error(`Immutable GitHub backup create failed for ${repositoryPath}: ${put.status} ${(await put.text()).slice(0,300)}. The existing version was not overwritten.`);
  const responseBody = await put.json().catch(()=>({}));
  let lastError = null;
  for (let attempt=1; attempt<=5; attempt++) {
    try {
      const remote = await githubReadRepositoryText(repositoryPath);
      if (remote != null && remote === content) return {verified:true, sha:responseBody?.content?.sha || null};
      lastError = new Error(`Read-back mismatch on attempt ${attempt}/5`);
    } catch (error) { lastError = error; }
    if (attempt < 5) await new Promise(resolve=>setTimeout(resolve,200*attempt));
  }
  throw new Error(`Immutable GitHub backup read-back verification failed for ${repositoryPath}: ${lastError?.message || 'content mismatch'}`);
}

async function githubWriteRepositoryText(repositoryPath, content, message) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub backup is not configured.');
  const metadataResponse = await githubRepositoryRequest(repositoryPath);
  let sha = null;
  if (metadataResponse && metadataResponse.ok) {
    const metadata = await metadataResponse.json();
    sha = metadata.sha || null;
    const existing = await githubReadRepositoryText(repositoryPath);
    if (existing != null && comparableGitHubText(existing) === comparableGitHubText(content)) return { unchanged:true, sha, verified:true, branch:config.branch };
  } else if (metadataResponse && metadataResponse.status !== 404) {
    throw new Error(`GitHub backup preflight failed for ${repositoryPath}: ${metadataResponse.status} ${(await metadataResponse.text()).slice(0,240)}`);
  }
  const body = { message: `${message} [skip render]`, content: Buffer.from(content, 'utf8').toString('base64'), branch: config.branch };
  if (sha) body.sha = sha;
  const put = await githubRepositoryRequest(repositoryPath, { method:'PUT', body:JSON.stringify(body) });
  if (!put.ok) throw new Error(`GitHub backup write failed for ${repositoryPath}: ${put.status} ${(await put.text()).slice(0,300)}`);
  const putBody = await put.json().catch(()=>({}));
  let readback = null;
  let lastReadError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      readback = await githubReadRepositoryText(repositoryPath);
      if (readback != null && comparableGitHubText(readback) === comparableGitHubText(content)) {
        return { unchanged:false, sha:putBody?.content?.sha || null, verified:true, branch:config.branch };
      }
      lastReadError = new Error(`Read-back content differs from submitted content (attempt ${attempt}/3)`);
    } catch (error) { lastReadError = error; }
    if (attempt < 3) await new Promise(resolve => setTimeout(resolve, attempt * 250));
  }
  const expected = crypto.createHash('sha256').update(String(content)).digest('hex').slice(0,12);
  const actual = readback == null ? 'missing' : crypto.createHash('sha256').update(String(readback)).digest('hex').slice(0,12);
  throw new Error(`GitHub backup text verification failed for ${repositoryPath} on branch ${config.branch} (expected ${expected}, received ${actual}): ${lastReadError?.message || 'content mismatch'}`);
}

async function githubWriteRepositoryBinary(repositoryPath, buffer, message) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub backup is not configured.');
  const metadataResponse = await githubRepositoryRequest(repositoryPath);
  let sha = null;
  if (metadataResponse && metadataResponse.ok) {
    const metadata = await metadataResponse.json();
    sha = metadata.sha || null;
  } else if (metadataResponse && metadataResponse.status !== 404) {
    throw new Error(`GitHub backup preflight failed for ${repositoryPath}: ${metadataResponse.status} ${(await metadataResponse.text()).slice(0,240)}`);
  }
  const body = { message: `${message} [skip render]`, content: buffer.toString('base64'), branch: config.branch };
  if (sha) body.sha = sha;
  const put = await githubRepositoryRequest(repositoryPath, { method:'PUT', body:JSON.stringify(body) });
  if (!put.ok) throw new Error(`GitHub backup archive write failed for ${repositoryPath}: ${put.status} ${(await put.text()).slice(0,300)}`);
  const verify = await githubRepositoryRequest(repositoryPath, { accept:'application/vnd.github.raw+json' });
  if (!verify.ok) throw new Error(`GitHub backup archive read-back failed for ${repositoryPath}: ${verify.status}`);
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  for await (const chunk of verify.body) { const b = Buffer.from(chunk); hash.update(b); bytes += b.length; }
  const actualHash = hash.digest('hex');
  const expectedHash = crypto.createHash('sha256').update(buffer).digest('hex');
  if (bytes !== buffer.length || actualHash !== expectedHash) throw new Error(`GitHub backup archive verification failed for ${repositoryPath} (expected ${expectedHash.slice(0,12)}, received ${actualHash.slice(0,12)}, bytes ${bytes}/${buffer.length})`);
  return { sha256:actualHash, size:bytes };
}

async function githubStreamRepositoryFileToResponse(repositoryPath, res, filename, expectedSha256) {
  const response = await githubRepositoryRequest(repositoryPath, { accept:'application/vnd.github.raw+json' });
  if (!response.ok) throw new Error(`GitHub backup download failed for ${repositoryPath}: ${response.status}`);
  const tempPath = path.join(require('os').tmpdir(), `sov-json-backup-download-${process.pid}-${Date.now()}.zip`);
  const hash = crypto.createHash('sha256');
  const hashTransform = new Transform({ transform(chunk, enc, callback) { hash.update(chunk); callback(null, chunk); } });
  try {
    await pipeline(Readable.fromWeb(response.body), hashTransform, fs.createWriteStream(tempPath, { flags:'wx' }));
    const actualHash = hash.digest('hex');
    if (!expectedSha256 || actualHash !== expectedSha256) throw new Error(`Downloaded GitHub backup hash verification failed (expected ${(expectedSha256||'missing').slice(0,12)}, received ${actualHash.slice(0,12)}).`);
    res.download(tempPath, filename, error => { try { fs.unlinkSync(tempPath); } catch (_) {} if (error && !res.headersSent) res.status(500).json({ok:false,error:'Verified backup download could not be sent.',detail:error.message}); });
  } catch (error) { try { fs.unlinkSync(tempPath); } catch (_) {} throw error; }
}

function ensureDrawingsDir() {
  fs.mkdirSync(DRAWINGS_DIR, { recursive: true });
}

function normalizeDrawingIndex(value) {
  const pages = Array.isArray(value?.pages) ? value.pages : [];
  return {
    version: 2,
    updatedAt: safeString(value?.updatedAt || new Date().toISOString()),
    fileName: 'drawings.pdf',
    sourceSha: safeString(value?.sourceSha).trim() || null,
    pages: pages.map((page, index) => ({
      page: Math.max(1, Number(page?.page || index + 1)),
      numbers: Array.isArray(page?.numbers) ? [...new Set(page.numbers.map(safeString).map(x=>x.trim()).filter(Boolean))] : [],
      text: safeString(page?.text).slice(0, 120000)
    }))
  };
}

function drawingDigits(value) {
  return safeString(value).replace(/\D/g, '');
}

// Engineering drawing OCR commonly confuses a capital I with the digit 1.
// Keep the original candidate for display, but add a narrow ambiguity key only
// for the common leading digit + I/1 + drawing-number suffix pattern. This
// avoids globally converting I↔1 and prevents unrelated numbers from matching.
function drawingNumberSearchKeys(value) {
  const source = safeString(value).trim().toUpperCase().replace(/[–—−]/g, '-').replace(/\s+/g, '');
  const keys = new Set();
  // Keep an alphanumeric key so formats such as G588, AB12 and A-4588
  // remain searchable. Separators are normalized while the original
  // candidate remains available for display/diagnostics internally.
  const textKey = source.replace(/[-\/_.]/g, '');
  if (textKey.length >= 4) keys.add(textKey);
  // Preserve the existing numeric/last-4 matching behavior.
  const digits = drawingDigits(source);
  if (digits.length >= 4) keys.add(digits);
  const ambiguous = source.match(/^(\d)([I1])[-\/]?(\d{4,})$/);
  if (ambiguous) keys.add(`${ambiguous[1]}${ambiguous[3]}`);
  return [...keys];
}

function drawingNumberCandidates(text) {
  const source = safeString(text).toUpperCase();
  const candidates = new Set();
  const patterns = [
    /\b[A-Z0-9]{1,16}(?:[-/][A-Z0-9]{1,16})+\b/g,
    /\b\d[A-ZI1]\d{4,}\b/g,
    /\b[A-Z]{1,4}\d{2,}\b/g,
    /\b\d{4,}\b/g
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const raw = safeString(match[0]).trim();
      if (drawingDigits(raw).length >= 4) candidates.add(raw);
    }
  }
  return [...candidates];
}

function hasStrongDrawingNumberCandidate(page) {
  const values = Array.isArray(page?.numbers) ? page.numbers : [];
  return values.some(value => {
    const source = safeString(value).trim().toUpperCase();
    if (drawingDigits(source).length < 4) return false;
    if (/^\d[A-ZI1][-\/]?\d{4,}$/.test(source)) return true;
    if (/^[A-Z]{1,4}[-\/]\d{2,}$/.test(source)) return true;
    if (/^[A-Z]{1,4}\d{2,}$/.test(source)) return true;
    if (/^\d{5,}$/.test(source)) return true;
    return false;
  });
}

function drawingIndexNeedsOcr(index) {
  return Boolean(index?.pages?.some(page => !hasStrongDrawingNumberCandidate(page)));
}

function mergeDrawingOcrPages(basePages, ocrPages) {
  if (!Array.isArray(basePages) || !basePages.length || !Array.isArray(ocrPages) || !ocrPages.length) return basePages;
  return basePages.map((page, index) => {
    const ocr = ocrPages[index];
    if (!ocr) return page;
    const ocrText = safeString(ocr.text).replace(/\s+/g, ' ').trim();
    const ocrNumbers = Array.isArray(ocr.numbers)
      ? [...new Set(ocr.numbers.map(safeString).map(x => x.trim()).filter(x => drawingDigits(x).length >= 4))]
      : drawingNumberCandidates(ocrText);
    const useOcr = !hasStrongDrawingNumberCandidate(page) || ocrNumbers.some(number => hasStrongDrawingNumberCandidate({numbers:[number]}));
    if (!useOcr) return page;
    return {
      ...page,
      text: [safeString(page.text), ocrText].filter(Boolean).join(' ').replace(/\s+/g, ' ').slice(0, 120000),
      numbers: [...new Set([...(Array.isArray(page.numbers) ? page.numbers : []), ...ocrNumbers])]
    };
  });
}

function extractPdfPageTexts(buffer) {
  const pdf = Buffer.isBuffer(buffer) ? Buffer.from(buffer) : Buffer.from(buffer || []);
  if (pdf.length < 5 || pdf.subarray(0, 5).toString('ascii') !== '%PDF-') {
    throw new Error('Drawing PDF is not a valid PDF.');
  }

  const raw = pdf.toString('latin1');
  const objects = new Map();
  const objectRegex = /(\d+)\s+(\d+)\s+obj([\s\S]*?)endobj/g;
  let match;
  while ((match = objectRegex.exec(raw))) {
    objects.set(`${match[1]} ${match[2]}`, match[3]);
  }

  function decodeStream(body, streamText) {
    let data = Buffer.from(streamText, 'latin1');
    const filterText = safeString(body).slice(0, 4000);
    const filters = [];
    if (/\/FlateDecode/.test(filterText)) filters.push('FlateDecode');
    if (/\/ASCII85Decode/.test(filterText)) filters.push('ASCII85Decode');

    // Most drawing PDFs use FlateDecode. Keep decoding conservative so a
    // malformed stream cannot turn a valid PDF into an unusable drawing state.
    if (filters.includes('FlateDecode')) {
      try { data = zlib.inflateSync(data); }
      catch (_) {
        try { data = zlib.inflateRawSync(data); } catch (_) {}
      }
    }
    return data;
  }

  function referencedObjects(body, key) {
    const result = [];
    const keyRegex = new RegExp(`${key}\\s+(\\[[\\s\\S]*?\\]|(?:\\d+\\s+\\d+\\s+R))`);
    const keyMatch = keyRegex.exec(body);
    if (!keyMatch) return result;
    const value = keyMatch[1];
    const refRegex = /(\d+)\s+(\d+)\s+R/g;
    let rm;
    while ((rm = refRegex.exec(value))) result.push(`${rm[1]} ${rm[2]}`);
    return result;
  }

  function textFromContentStream(stream) {
    const textParts = [];
    const literal = /\(((?:\\.|[^\\)])*)\)\s*Tj/g;
    let lm;
    while ((lm = literal.exec(stream))) {
      const value = lm[1]
        .replace(/\\([\\()])/g, '$1')
        .replace(/\\n/g, ' ')
        .replace(/\\r/g, ' ')
        .replace(/\\t/g, ' ');
      textParts.push(value);
    }

    const hex = /<([0-9A-Fa-f]+)>\s*Tj/g;
    let hm;
    while ((hm = hex.exec(stream))) {
      const bytes = Buffer.from(hm[1], 'hex');
      let value = bytes.toString('utf16be');
      if (!value || /[\u0000-\u0008]/.test(value)) value = bytes.toString('latin1');
      textParts.push(value.replace(/\u0000/g, ''));
    }

    // TJ arrays are common in generated engineering PDFs.
    const tjArray = /\[((?:[^\]])*)\]\s*TJ/g;
    let am;
    while ((am = tjArray.exec(stream))) {
      const body = am[1];
      const pieces = [];
      const tokenRegex = /\(((?:\\.|[^\\)])*)\)|<([0-9A-Fa-f]+)>/g;
      let tm;
      while ((tm = tokenRegex.exec(body))) {
        if (tm[1] != null) {
          pieces.push(tm[1].replace(/\\([\\()])/g, '$1').replace(/\\[nrt]/g, ' '));
        } else {
          const bytes = Buffer.from(tm[2], 'hex');
          let value = bytes.toString('utf16be');
          if (!value || /[\u0000-\u0008]/.test(value)) value = bytes.toString('latin1');
          pieces.push(value.replace(/\u0000/g, ''));
        }
      }
      if (pieces.length) textParts.push(pieces.join(''));
    }

    return textParts.join(' ');
  }

  const pageObjectIds = [];
  const seenPages = new Set();
  const addPageTree = (objectId) => {
    if (!objectId || seenPages.has(objectId)) return;
    const body = objects.get(objectId);
    if (!body) return;
    seenPages.add(objectId);
    if (/\/Type\s*\/Pages(?:\s|\/|$)/.test(body)) {
      for (const child of referencedObjects(body, '/Kids')) addPageTree(child);
      return;
    }
    if (/\/Type\s*\/Page(?:\s|\/|$)/.test(body)) pageObjectIds.push(objectId);
  };

  // Follow the PDF page tree so returned page numbers match the actual PDF
  // page order instead of relying on arbitrary object-number order.
  for (const [objectId, body] of objects.entries()) {
    if (/\/Type\s*\/Catalog(?:\s|\/|$)/.test(body)) {
      const roots = referencedObjects(body, '/Pages');
      for (const root of roots) addPageTree(root);
    }
  }
  if (!pageObjectIds.length) {
    for (const [objectId, body] of objects.entries()) {
      if (/\/Type\s*\/Page(?:\s|\/|$)/.test(body)) pageObjectIds.push(objectId);
    }
  }

  const pages = [];
  for (const objectId of pageObjectIds) {
    const body = objects.get(objectId);
    if (!body) continue;

    const contentBodies = [];
    const directStreamRegex = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
    let sm;
    while ((sm = directStreamRegex.exec(body))) contentBodies.push(decodeStream(body, sm[1]));

    // Normal PDFs frequently store page content in separate /Contents refs.
    // Resolve both a single reference and an array of references.
    for (const ref of referencedObjects(body, '/Contents')) {
      const referencedBody = objects.get(ref);
      if (!referencedBody) continue;
      const referencedStreamRegex = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
      let rsm;
      while ((rsm = referencedStreamRegex.exec(referencedBody))) {
        contentBodies.push(decodeStream(referencedBody, rsm[1]));
      }
    }

    const text = contentBodies.map(stream => textFromContentStream(stream.toString('latin1')))
      .join(' ').replace(/\s+/g, ' ').trim();

    pages.push({ page: pages.length + 1, text, numbers: drawingNumberCandidates(text) });
  }

  return pages;
}

async function githubDrawingRequest(relativePath, options = {}) {
  const config = githubConfig();
  if (!config) return null;
  const [pathPart, queryPart] = String(relativePath || '').split(/\?(.+)/, 2);
  const safePath = pathPart.split('/').filter(Boolean).map(encodeURIComponent).join('/');
  const api = `https://api.github.com/repos/${config.repo}/contents/${DRAWINGS_GITHUB_PATH}/${safePath}${queryPart ? `?${queryPart}` : ''}`;
  const headers = {
    Authorization: `Bearer ${config.token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'sov-engineering-app',
    ...(options.body ? {'Content-Type':'application/json'} : {})
  };
  return fetch(api, {...options, headers});
}

async function githubReadDrawingFile(relativePath) {
  const config = githubConfig();
  if (!config) return null;
  const response = await githubDrawingRequest(`${relativePath}?ref=${encodeURIComponent(config.branch)}`);
  if (!response) return null;
  const responseText = await response.text();
  if (response.status === 404) return null;
  if (!response.ok) {
    let detail = responseText;
    try { detail = JSON.stringify(JSON.parse(responseText)); } catch (_) {}
    throw new Error(`GitHub drawing read failed: HTTP ${response.status}${detail ? ` - ${detail.slice(0, 300)}` : ''}`);
  }

  let body;
  try { body = JSON.parse(responseText); }
  catch (_) { throw new Error('GitHub drawing read returned invalid JSON.'); }

  let buffer = Buffer.alloc(0);
  if (safeString(body.content).trim()) {
    try { buffer = Buffer.from(body.content.replace(/\s+/g, ''), 'base64'); }
    catch (_) { throw new Error('GitHub drawing PDF Base64 decoding failed.'); }
  }

  if (!buffer.length && body.download_url) {
    const rawResponse = await fetch(body.download_url, {
      headers:{Authorization:`Bearer ${config.token}`,Accept:'application/octet-stream','User-Agent':'sov-engineering-app'}
    });
    if (!rawResponse.ok) {
      const detail = await rawResponse.text().catch(()=> '');
      throw new Error(`GitHub drawing binary download failed: HTTP ${rawResponse.status}${detail ? ` - ${detail.slice(0, 200)}` : ''}`);
    }
    buffer = Buffer.from(await rawResponse.arrayBuffer());
  }

  if (!buffer.length) throw new Error(`GitHub drawing file is empty: ${relativePath}`);
  return { buffer:Buffer.from(buffer), sha:body.sha || null };
}

let drawingRuntime = { initialized:false, available:false, pdf:null, index:null, sha:null, updatedAt:'' };
let drawingInitializationPromise = null;

function clearDrawingRuntime() {
  drawingRuntime = { initialized:false, available:false, pdf:null, index:null, sha:null, updatedAt:'' };
}

function drawingRuntimeResult(source='github') {
  return {
    source,
    available:Boolean(drawingRuntime.available && drawingRuntime.pdf?.length && drawingRuntime.index?.pages?.length),
    index:drawingRuntime.index,
    pdf:drawingRuntime.pdf
  };
}

async function githubWriteDrawingFile(relativePath, buffer, message) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub Drawings configuration is missing.');
  const current = await githubReadDrawingFile(relativePath);
  const bytes = Buffer.isBuffer(buffer) ? Buffer.from(buffer) : Buffer.from(buffer || []);
  if (!bytes.length) throw new Error('Cannot write an empty drawing file.');
  if (current?.buffer && current.buffer.equals(bytes)) return true;
  const body = {
    message: `${message} [skip render]`,
    content: bytes.toString('base64'),
    branch: config.branch
  };
  if (current?.sha) body.sha = current.sha;
  const response = await githubDrawingRequest(relativePath, {method:'PUT', body:JSON.stringify(body)});
  if (!response?.ok) {
    let detail = '';
    try {
      const errorBody = await response.json();
      detail = safeString(errorBody?.message || errorBody?.error || '').trim();
    } catch (_) {
      try { detail = (await response?.text?.() || '').slice(0,300).trim(); } catch (_) {}
    }
    throw new Error(`GitHub drawing write failed: HTTP ${response?.status || 'unknown'}${detail ? ` - ${detail}` : ''}`);
  }
  return true;
}

async function githubReadDrawingFileWithRetry(relativePath, attempts=3, validate=null) {
  let lastError=null;
  for(let attempt=0;attempt<Math.max(1,attempts);attempt++) {
    try {
      const result=await githubReadDrawingFile(relativePath);
      if(result?.buffer?.length && (!validate || validate(result))) return result;
      lastError=new Error(`GitHub drawing file is not yet verified: ${relativePath}`);
    } catch(error) { lastError=error; }
    if(attempt+1<attempts) await new Promise(resolve=>setTimeout(resolve,250*(attempt+1)));
  }
  if(lastError) throw lastError;
  return null;
}

async function githubDeleteDrawingFile(relativePath, message) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub Drawings configuration is missing.');
  const current = await githubReadDrawingFile(relativePath);
  if (!current?.sha) return false;
  const response = await githubDrawingRequest(relativePath, {method:'DELETE', body:JSON.stringify({message:`${message} [skip render]`,sha:current.sha,branch:config.branch})});
  if (!response?.ok && response?.status !== 404) {
    let detail = '';
    try {
      const errorBody = await response.json();
      detail = safeString(errorBody?.message || errorBody?.error || '').trim();
    } catch (_) {}
    throw new Error(`GitHub drawing delete failed: HTTP ${response.status}${detail ? ` - ${detail}` : ''}`);
  }
  return true;
}

function loadDrawingIndexLocal() {
  ensureDrawingsDir();
  if (!fs.existsSync(DRAWING_INDEX_LOCAL)) return null;
  try {
    const stored = fs.readFileSync(DRAWING_INDEX_LOCAL);
    return normalizeDrawingIndex(JSON.parse(decryptText(stored.toString('utf8'))));
  } catch (_) { return null; }
}

function saveDrawingIndexLocal(index) {
  ensureDrawingsDir();
  const normalized = normalizeDrawingIndex(index);
  fs.writeFileSync(DRAWING_INDEX_LOCAL, encryptText(JSON.stringify(normalized, null, 2)), 'utf8');
}

function loadDrawingPdfLocal() {
  ensureDrawingsDir();
  if (!fs.existsSync(DRAWING_PDF_LOCAL)) return null;
  try {
    return decryptBuffer(fs.readFileSync(DRAWING_PDF_LOCAL));
  } catch (_) { return null; }
}

function saveDrawingPdfLocal(pdf) {
  ensureDrawingsDir();
  fs.writeFileSync(DRAWING_PDF_LOCAL, encryptBuffer(pdf));
}

async function processDrawingPdf(plainPdf, options = {}) {
  const pdf = Buffer.from(plainPdf || []);
  if (pdf.length < 5 || pdf.subarray(0, 5).toString('ascii') !== '%PDF-') {
    throw new Error('Drawing PDF is not a valid PDF.');
  }
  if (pdf.length > MAX_DRAWING_PDF_BYTES) {
    throw new Error(`Drawing PDF is too large. Maximum allowed size is ${Math.round(MAX_DRAWING_PDF_BYTES / 1024 / 1024)} MB.`);
  }

  let extractedPages = [];
  try {
    extractedPages = extractPdfPageTexts(Buffer.from(pdf));
  } catch (error) {
    console.warn('Drawing PDF text extraction failed; continuing with page metadata:', error.message);
  }

  const fallbackPages = Array.isArray(options.fallbackPages) ? options.fallbackPages : [];
  let pages = extractedPages;

  // Client OCR metadata is supplemental only. It is merged with the server's
  // current PDF page structure and is never allowed to replace the PDF itself.
  if (fallbackPages.length) {
    if (pages.length === fallbackPages.length) {
      pages = mergeDrawingOcrPages(pages, fallbackPages);
    } else if (!pages.length) {
      pages = fallbackPages.map((page, index) => ({
        page: Math.max(1, Number(page?.page || index + 1)),
        text: safeString(page?.text).replace(/\s+/g, ' ').trim().slice(0, 120000),
        numbers: Array.isArray(page?.numbers)
          ? [...new Set(page.numbers.map(safeString).map(x => x.trim()).filter(x => drawingDigits(x).length >= 4))]
          : drawingNumberCandidates(page?.text || '')
      }));
    }
  }

  if (!pages.length) {
    // A valid image-only PDF can have no selectable text. Build a page skeleton
    // from the PDF page tree so the frontend can render each page and perform
    // OCR against the actual GitHub PDF.
    const rawPdfText = pdf.toString('latin1');
    const markerMatches = rawPdfText.match(/\/Type\s*\/Page(?:\s|[>/])/g) || [];
    const pageCount = Math.max(1, markerMatches.length);
    pages = Array.from({length: pageCount}, (_, index) => ({
      page: index + 1,
      text: '',
      numbers: []
    }));
  }

  const index = normalizeDrawingIndex({
    version: 2,
    fileName: 'drawings.pdf',
    updatedAt: safeString(options.updatedAt || new Date().toISOString()),
    sourceSha: safeString(options.sha).trim() || null,
    pages
  });

  return {
    available: Boolean(pdf.length && index.pages.length),
    pdf: Buffer.from(pdf),
    index,
    sourceSha: safeString(options.sha).trim() || null
  };
}

async function loadDrawingPdfFromGitHub(options = {}) {
  const config = githubConfig();
  if (!config) {
    clearDrawingRuntime();
    return drawingRuntimeResult('github-unavailable');
  }

  const force = options.force === true;
  if (!force && drawingRuntime.initialized && drawingRuntime.available && drawingRuntime.pdf?.length && drawingRuntime.index?.pages?.length) {
    return drawingRuntimeResult('github-runtime');
  }

  const remotePdf = await githubReadDrawingFile(DRAWING_PDF_GITHUB_FILE);
  if (!remotePdf?.buffer?.length) {
    clearDrawingRuntime();
    return drawingRuntimeResult('github');
  }

  let plainPdf = Buffer.from(remotePdf.buffer);
  if (plainPdf.subarray(0, 5).toString('ascii') !== '%PDF-') {
    try {
      plainPdf = Buffer.from(decryptBuffer(plainPdf));
    } catch (_) {
      throw new Error('GitHub drawings.pdf is not a valid PDF.');
    }
  }
  if (plainPdf.subarray(0, 5).toString('ascii') !== '%PDF-') {
    throw new Error('GitHub drawings.pdf validation failed.');
  }

  // An index is only reusable when it belongs to the exact GitHub blob SHA.
  let remoteIndex = null;
  try {
    const indexFile = await githubReadDrawingFile(DRAWING_INDEX_GITHUB_FILE);
    if (indexFile?.buffer?.length) {
      let indexBuffer = Buffer.from(indexFile.buffer);
      try {
        const indexText = indexBuffer.toString('utf8');
        if (indexText.trim().startsWith('{')) {
          remoteIndex = normalizeDrawingIndex(JSON.parse(indexText));
        } else {
          remoteIndex = normalizeDrawingIndex(JSON.parse(decryptText(indexText)));
        }
      } catch (_) {
        try {
          remoteIndex = normalizeDrawingIndex(JSON.parse(decryptText(indexBuffer.toString('utf8'))));
        } catch (_) {
          remoteIndex = null;
        }
      }
    }
  } catch (indexError) {
    // A missing/stale/broken index must never make a valid drawings.pdf unusable.
    console.warn('Drawing search index could not be loaded; rebuilding from current PDF:', indexError.message);
    remoteIndex = null;
  }

  let processed;
  if (remoteIndex?.pages?.length && safeString(remoteIndex.sourceSha).trim() === safeString(remotePdf.sha).trim()) {
    processed = {
      available: true,
      pdf: Buffer.from(plainPdf),
      index: remoteIndex,
      sourceSha: remotePdf.sha || null
    };
  } else {
    processed = await processDrawingPdf(Buffer.from(plainPdf), {
      sha: remotePdf.sha,
      updatedAt: new Date().toISOString()
    });
  }

  drawingRuntime = {
    initialized: true,
    available: Boolean(processed.available),
    pdf: Buffer.from(processed.pdf),
    index: normalizeDrawingIndex(processed.index),
    sha: remotePdf.sha || processed.sourceSha || null,
    updatedAt: safeString(processed.index?.updatedAt || new Date().toISOString())
  };

  // Keep the existing encrypted runtime cache for compatibility/performance,
  // but never use it to decide whether the persistent GitHub drawing exists.
  try {
    saveDrawingPdfLocal(drawingRuntime.pdf);
    saveDrawingIndexLocal(drawingRuntime.index);
  } catch (cacheError) {
    console.warn('Drawing runtime cache update failed; GitHub remains source of truth:', cacheError.message);
  }

  return drawingRuntimeResult('github');
}

async function restoreDrawingsFromGithubIfNeeded(options = {}) {
  const config = githubConfig();
  if (!config) {
    const localPdf = loadDrawingPdfLocal();
    const localIndex = loadDrawingIndexLocal();
    if (!drawingRuntime.initialized && localPdf?.length && localIndex?.pages?.length) {
      drawingRuntime = {initialized:true,available:true,pdf:Buffer.from(localPdf),index:localIndex,sha:null,updatedAt:localIndex.updatedAt||''};
    }
    return drawingRuntimeResult('local-cache');
  }

  // GitHub remains the source of truth. Force/initialization always retrieves
  // the current target from GitHub; normal calls reuse the authenticated
  // runtime copy so Search does not download the entire PDF for every click.
  return loadDrawingPdfFromGitHub({force:options.forceRemote === true});
}

/* ---------------------------------------------------------
 * Encrypted Employee JSON on private GitHub
 * --------------------------------------------------------- */
const EMPLOYEE_JSON_LOCAL = path.join(CSV_ROOT, 'employees.json');
let employeeCache = null;
let employeeCacheLoadedAt = 0;
const EMPLOYEE_CACHE_TTL_MS = 5 * 60 * 1000;

function employeeJsonRelativePath() {
  return safeString(
    process.env.GITHUB_EMPLOYEE_JSON_PATH ||
    process.env.GITHUB_EMPLOYEE_PATH ||
    'employees.json'
  ).replace(/^\/+|\/+$/g, '');
}

function encryptJsonText(value) {
  return encryptText(JSON.stringify(value, null, 2));
}

function decryptJsonText(storedText) {
  const plain = decryptText(storedText);
  let parsed;
  try {
    parsed = JSON.parse(plain || '{}');
  } catch (error) {
    throw new Error('Employee JSON data is invalid or corrupted.');
  }
  return Array.isArray(parsed) ? parsed : (Array.isArray(parsed.employees) ? parsed.employees : []);
}

function employeePublicView(employee) {
  if (!employee || typeof employee !== 'object') return null;
  const out = { ...employee };
  delete out.pin;
  delete out.password;
  delete out.pinHash;
  delete out.passwordHash;
  return out;
}

function publicEmployees(employees) {
  return (Array.isArray(employees) ? employees : [])
    .map(employeePublicView)
    .filter(Boolean)
    .filter(employee => !isDeleted(employee))
    .sort(compareEmployeeId);
}

async function readEmployeeJsonFromGitHub(force = false) {
  if (!force && Array.isArray(employeeCache) && Date.now() - employeeCacheLoadedAt < EMPLOYEE_CACHE_TTL_MS) {
    return employeeCache.map(x => ({ ...x }));
  }

  const loadLocalEncryptedEmployeeCache = () => {
    if (!fs.existsSync(EMPLOYEE_JSON_LOCAL)) return null;
    try {
      const raw = fs.readFileSync(EMPLOYEE_JSON_LOCAL, 'utf8');
      const localEmployees = decryptJsonText(raw).map(normalizeEmployee).filter(Boolean);
      employeeCache = localEmployees;
      employeeCacheLoadedAt = Date.now();
      return localEmployees.map(x => ({ ...x }));
    } catch (error) {
      console.error('Encrypted local employee cache read failed:', error.message);
      return null;
    }
  };

  const config = githubConfig();
  if (!config) {
    /* Local encrypted cache is only a temporary server cache; it is never plaintext. */
    const localEmployees = loadLocalEncryptedEmployeeCache();
    if (localEmployees) return localEmployees;
    throw new Error('GitHub employee storage is not configured.');
  }

  try {
    const remote = await githubReadFile(employeeJsonRelativePath());
    if (!remote || remote.content == null) {
      // A missing remote employee file represents an empty employee store only
      // when there is no preserved local encrypted cache. Never discard a valid
      // local cache merely because a remote read is temporarily unavailable.
      const localEmployees = loadLocalEncryptedEmployeeCache();
      if (localEmployees) return localEmployees;
      employeeCache = [];
      employeeCacheLoadedAt = Date.now();
      return [];
    }

    const employees = decryptJsonText(remote.content)
      .map(normalizeEmployee)
      .filter(Boolean);

    employeeCache = employees;
    employeeCacheLoadedAt = Date.now();
    fs.mkdirSync(path.dirname(EMPLOYEE_JSON_LOCAL), { recursive: true });
    fs.writeFileSync(EMPLOYEE_JSON_LOCAL, remote.content, 'utf8');
    return employees.map(x => ({ ...x }));
  } catch (error) {
    // State reads must not turn a transient GitHub outage into a false
    // authentication/data-loss condition when the last verified encrypted
    // employee snapshot is still available locally.
    const localEmployees = loadLocalEncryptedEmployeeCache();
    if (localEmployees) return localEmployees;
    throw error;
  }
}

async function writeEmployeeJsonToGitHub(employees) {
  const config = githubConfig();
  if (!config) throw new Error('GitHub employee storage is not configured.');

  const normalized = (Array.isArray(employees) ? employees : [])
    .map(normalizeEmployee)
    .filter(Boolean)
    .sort(compareEmployeeId);

  validateEmployeeIds(normalized);
  const encrypted = encryptJsonText({ version: 1, employees: normalized });

  const ok = await githubWriteFile(
    employeeJsonRelativePath(),
    encrypted,
    'Update SOV Engineering encrypted employee data'
  );
  if (!ok) throw new Error('GitHub employee save failed.');

  // Do not report an Employee Add/Edit/Delete as successful until the exact
  // encrypted employee document can be read back and validated.
  const verifiedRemote = await githubReadFile(employeeJsonRelativePath());
  if (!verifiedRemote?.content) throw new Error('GitHub employee save verification failed.');
  const verifiedEmployees = decryptJsonText(verifiedRemote.content)
    .map(normalizeEmployee)
    .filter(Boolean)
    .sort(compareEmployeeId);
  if (JSON.stringify(verifiedEmployees) !== JSON.stringify(normalized)) {
    throw new Error('GitHub employee save verification failed.');
  }

  employeeCache = normalized.map(x => ({ ...x }));
  employeeCacheLoadedAt = Date.now();
  fs.mkdirSync(path.dirname(EMPLOYEE_JSON_LOCAL), { recursive: true });
  fs.writeFileSync(EMPLOYEE_JSON_LOCAL, encrypted, 'utf8');
  return true;
}

async function migrateLegacyEmployeeCsvIfNeeded() {
  const config = githubConfig();
  if (!config) return;
  const remote = await githubReadFile(employeeJsonRelativePath());
  if (remote?.content != null) {
    try {
      const rawEmployees = decryptJsonText(remote.content);
      employeeCache = rawEmployees.map(normalizeEmployee).filter(Boolean);
      employeeCacheLoadedAt = Date.now();
      fs.mkdirSync(path.dirname(EMPLOYEE_JSON_LOCAL), { recursive: true });
      const local = fs.existsSync(EMPLOYEE_JSON_LOCAL) ? fs.readFileSync(EMPLOYEE_JSON_LOCAL, 'utf8') : '';
      if (!local || local !== remote.content) fs.writeFileSync(EMPLOYEE_JSON_LOCAL, remote.content, 'utf8');
      // The internal employee ID is the stable identity key. Persist it into
      // the canonical `id` field only when that field is missing; Employee Code
      // remains a separate display/reference value and is never substituted.
      const needsIdBackfill = rawEmployees.some(employee => employee && typeof employee === 'object' && !safeString(employee.id).trim() && !!employeeIdOf(employee));
      if (needsIdBackfill) {
        await writeEmployeeJsonToGitHub(employeeCache);
        console.log('Backfilled missing employee record IDs using existing internal Employee IDs.');
      }
    } catch (error) {
      throw new Error(`Employee JSON data is invalid or corrupted: ${error.message}`);
    }
    return;
  }

  let legacy = [];
  try {
    legacy = readAllEntityRecords(EMPLOYEE_KEY)
      .map(normalizeEmployee)
      .filter(Boolean);
  } catch (_) {}

  if (legacy.length) {
    await writeEmployeeJsonToGitHub(legacy);
  } else {
    await writeEmployeeJsonToGitHub([]);
  }
}

async function getEmployeesFromStore(force = false) {
  return readEmployeeJsonFromGitHub(force);
}

function getCachedEmployeesIncludingDeleted() {
  return Array.isArray(employeeCache) ? employeeCache.map(x => ({ ...x })) : [];
}

function getEmployeesCsv() {
  return publicEmployees(getCachedEmployeesIncludingDeleted());
}

async function syncCsvFilesToGitHub(
  entity,
  records,
  options = {}
) {
  if (entity === EMPLOYEE_KEY) return;
  if (!githubConfig()) {
    return;
  }

  const months =
    new Set();

  const financialYears =
    new Set();

  for (
    const record of
    ensureSoftDeleteField(
      records
    )
  ) {
    const date =
      recordDate(
        entity,
        record
      );

    months.add(
      monthFor(date)
    );

    financialYears.add(
      fyFor(date)
    );
  }

  const requestedMonths = Array.isArray(options.months) && options.months.length
    ? new Set(options.months)
    : new Set([...months, ...getMonthsForEntity(entity)]);
  const requestedFinancialYears = Array.isArray(options.financialYears) && options.financialYears.length
    ? new Set(options.financialYears)
    : new Set([...financialYears, ...getFinancialYearsForEntity(entity)]);

  months.clear();
  for (const month of requestedMonths) months.add(month);
  financialYears.clear();
  for (const fy of requestedFinancialYears) financialYears.add(fy);

  for (
    const month of months
  ) {
    const file =
      monthlyFile(month);

    const content =
      fs.existsSync(file)
        ? fs.readFileSync(
            file,
            'utf8'
          )
        : encryptText(
            CSV_HEADERS.join(',') +
            '\n'
          );

    const monthSyncStartedAt = Date.now();
    const monthlySaveResult = await githubWriteFile(
      `monthly/${month}.csv`,
      content,
      `Update SOV Engineering monthly CSV ${month}`,
      { returnDetails:true }
    );
    const monthlySaved = monthlySaveResult === true || monthlySaveResult?.ok === true;
    if (githubConfig() && monthlySaved && monthlySaveResult?.unchanged === true &&
        monthlySaveResult.content != null && sameStoredContent(monthlySaveResult.content, content)) {
      console.info(`[CSV sync timing] entity=${entity} month=${month} durationMs=${Date.now()-monthSyncStartedAt} outcome=unchanged-verified`);
    } else if (githubConfig() && monthlySaved) {
      // A successful Contents API PUT can be visible before all subsequent
      // branch-pinned reads return the new blob. Retry verification, but never
      // treat a mismatch as success. This is intentionally bounded so a real
      // stale/conflicting or corrupted remote file still fails with diagnostics.
      let verifiedRemote = null;
      let lastReadError = null;
      let verified = false;
      const verificationAttempts = 5;
      for (let attempt = 0; attempt < verificationAttempts; attempt++) {
        try {
          verifiedRemote = await githubReadFile(`monthly/${month}.csv`);
          lastReadError = null;
          if (verifiedRemote?.content && sameStoredContent(verifiedRemote.content, content)) {
            verified = true;
            break;
          }
        } catch (error) {
          lastReadError = error;
        }
        if (attempt < verificationAttempts - 1) {
          await new Promise(resolve => setTimeout(resolve, 200 * (attempt + 1)));
        }
      }
      if (!verified) {
        const expectedInfo = storedContentDiagnostic(content);
        const remoteInfo = storedContentDiagnostic(verifiedRemote?.content);
        const readError = lastReadError ? `; lastReadError=${safeString(lastReadError.message).slice(0, 240)}` : '';
        throw new Error(
          `GitHub monthly CSV verification failed for ${month} after ${verificationAttempts} attempts; ` +
          `remotePresent=${remoteInfo.present}; ` +
          `expectedBytes=${expectedInfo.rawLength}; remoteBytes=${remoteInfo.rawLength}; ` +
          `expectedSha256=${expectedInfo.rawSha256}; remoteSha256=${remoteInfo.rawSha256}; ` +
          `expectedNormalizedSha256=${expectedInfo.normalizedSha256}; ` +
          `remoteNormalizedSha256=${remoteInfo.normalizedSha256}; ` +
          `expectedEncrypted=${expectedInfo.encrypted}; remoteEncrypted=${remoteInfo.encrypted}${readError}.`
        );
      }
      console.info(`[CSV sync timing] entity=${entity} month=${month} durationMs=${Date.now()-monthSyncStartedAt} outcome=uploaded-and-verified`);
    }
  }

  for (
    const fy of financialYears
  ) {
    const file =
      financialYearFile(fy);

    const content =
      fs.existsSync(file)
        ? fs.readFileSync(
            file,
            'utf8'
          )
        : encryptText(
            CSV_HEADERS.join(',') +
            '\n'
          );

    const fySaved = await githubWriteFile(
      `financial-years/${fy}.csv`,
      content,
      `Update SOV Engineering financial year CSV ${fy}`
    );
    if (githubConfig() && fySaved) {
      const verifiedRemote = await githubReadFile(`financial-years/${fy}.csv`);
      if (!verifiedRemote?.content || !sameStoredContent(verifiedRemote.content, content)) {
        throw new Error(`GitHub financial-year CSV verification failed for ${fy}.`);
      }
    }
  }

  if ((options.includeIndex !== false) && fs.existsSync(INDEX_FILE)) {
    const indexContent = fs.readFileSync(INDEX_FILE, 'utf8');
    const indexSaved = await githubWriteFile(
      '_index.csv',
      indexContent,
      'Update SOV Engineering CSV index'
    );
    if (githubConfig() && indexSaved) {
      const verifiedRemote = await githubReadFile('_index.csv');
      if (!verifiedRemote?.content || !sameStoredContent(verifiedRemote.content, indexContent)) {
        throw new Error('GitHub CSV index verification failed.');
      }
    }
  }
}

async function githubListDirectory(relativePath) {
  const config = githubConfig();
  if (!config) return [];

  const response = await githubRequest(
    `${config.basePath}/${relativePath}?ref=${encodeURIComponent(config.branch)}`
  );

  if (response.status === 404) return [];
  if (!response.ok) {
    throw new Error(`GitHub CSV directory read failed: ${response.status}`);
  }

  const body = await response.json();
  return Array.isArray(body) ? body : [];
}

// Operational JSON partitions are the fast read store, but Render's local
// filesystem may be disposable. Mirror every changed encrypted partition to
// the same configured private GitHub repository as the existing CSV storage.
// A write is not acknowledged until the exact partition can be read back.
async function syncOperationalJsonPartitionsToGitHub(entity, filePaths) {
  if (!githubConfig()) return { uploaded: 0, verified: 0 };
  const queue = [];
  const queued = new Set();
  const addFile = file => {
    if (typeof file !== 'string' || !file.startsWith(JSON_STORE_ROOT + path.sep)) return;
    if (!queued.has(file)) { queue.push(file); queued.add(file); }
  };
  for (const file of (Array.isArray(filePaths) ? filePaths : [])) addFile(file);
  let verified = 0;
  let pendingNeedsPersist = false;
  let iterations = 0;
  const maxIterations = Math.max(100, queue.length * 20);

  while (queue.length) {
    if (++iterations > maxIterations) {
      throw new Error(`Operational JSON mirror reconciliation exceeded its safety limit for ${entity}.`);
    }
    const file = queue.shift();
    queued.delete(file);
    const relative = path.relative(CSV_ROOT, file).split(path.sep).join('/');
    if (!relative.startsWith('operational-json/')) continue;

    let completed = false;
    let lastError = null;
    for (let attempt = 1; attempt <= 5 && !completed; attempt++) {
      const remote = await githubReadFile(relative);
      let remoteRows = [];
      if (remote?.content != null) {
        try {
          const parsed = JSON.parse(decryptText(remote.content));
          if (!Array.isArray(parsed)) throw new Error('partition root is not an array');
          remoteRows = parsed.filter(record => record && typeof record === 'object' && recordId(record));
        } catch (error) {
          throw new Error(`GitHub operational JSON partition is unreadable (${relative}): ${error.message}`);
        }
      }
      const localRows = fs.existsSync(file) ? readJsonPartition(file) : [];
      const mergedById = new Map();
      const cachedById = new Map((entityAllJsonCache.get(entity) || []).map(record => [recordId(record), record]));
      for (const record of remoteRows) {
        const id = recordId(record);
        if (!id) continue;
        const cached = cachedById.get(id);
        mergedById.set(id, cached
          ? mergeOperationalSnapshot(entity, record, cached)
          : { ...record });
      }
      // The in-memory cache knows about a record that may have moved out of
      // this old bucket during the current mutation. Reconcile only IDs that
      // exist in this partition, so a stale remote copy cannot be reintroduced
      // into its former date partition and unrelated buckets are not queued.
      for (const record of localRows) {
        const id = recordId(record);
        const old = mergedById.get(id);
        mergedById.set(id, old
          ? mergeOperationalSnapshot(entity, old, record)
          : { ...record });
      }

      const rowsForThisPartition = [];
      for (const record of mergedById.values()) {
        const targetFile = jsonPartitionForRecord(entity, record);
        if (targetFile === file) {
          rowsForThisPartition.push(record);
          continue;
        }
        // A newer historical-date edit may move an ID to a different bucket.
        // Stage it in the correct local partition and queue that partition; the
        // old partition is rewritten without the moved record below.
        const targetRows = fs.existsSync(targetFile) ? readJsonPartition(targetFile) : [];
        const targetById = new Map(targetRows.map(item => [recordId(item), { ...item }]));
        const targetOld = targetById.get(recordId(record));
        targetById.set(recordId(record), targetOld
          ? mergeOperationalSnapshot(entity, targetOld, record)
          : { ...record });
        writeJsonPartition(targetFile, [...targetById.values()]);
        addFile(targetFile);
      }

      writeJsonPartition(file, rowsForThisPartition);

      // Keep the in-memory entity cache aware of records discovered in the
      // remote bucket, including records written by another app instance.
      const cacheById = new Map((entityAllJsonCache.get(entity) || []).map(record => [recordId(record), { ...record }]));
      for (const record of mergedById.values()) {
        const id = recordId(record);
        const old = cacheById.get(id);
        cacheById.set(id, old
          ? mergeOperationalSnapshot(entity, old, record)
          : { ...record });
      }
      entityAllJsonCache.set(entity, [...cacheById.values()]);

      // A remote partition can contain a newer version written by another
      // server instance. Update existing overlays by ID so an older in-memory
      // Work Order cannot overwrite that version during the next read.
      const mergeExistingOverlayRows = rows => {
        if (!Array.isArray(rows)) return false;
        let changed = false;
        const indexById = new Map(rows.map((record, index) => [recordId(record), index]));
        for (const record of mergedById.values()) {
          const id = recordId(record);
          if (!indexById.has(id)) continue;
          const index = indexById.get(id);
          const old = rows[index];
          const merged = mergeOperationalSnapshot(entity, old, record);
          if (!sameJsonValue(old, merged)) { rows[index] = merged; changed = true; }
        }
        return changed;
      };
      mergeExistingOverlayRows(dailyState?.entities?.[entity]);
      if (pendingStateLoaded && mergeExistingOverlayRows(pendingState?.entities?.[entity])) pendingNeedsPersist = true;

      const content = fs.readFileSync(file, 'utf8');
      if (remote?.content != null && sameStoredContent(remote.content, content)) {
        try {
          await verifyGitHubJsonDocument(relative, content, `Operational JSON partition ${relative}`);
          completed = true;
          verified++;
          break;
        } catch (error) {
          lastError = error;
          if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 200 * attempt));
          continue;
        }
      }

      const config = githubConfig();
      const body = {
        message: `Update SOV ${entity} year-wise operational JSON partition [skip render]`,
        content: Buffer.from(content, 'utf8').toString('base64'),
        branch: config.branch
      };
      if (remote?.sha) body.sha = remote.sha;
      const response = await githubRequest(`${config.basePath}/${relative}`, {
        method: 'PUT',
        body: JSON.stringify(body)
      });
      if (!response.ok) {
        const detail = (await response.text()).slice(0, 300);
        if ((response.status === 409 || response.status === 422) && attempt < 5) {
          lastError = new Error(`GitHub operational JSON concurrent update (${response.status}).`);
          await new Promise(resolve => setTimeout(resolve, 150 * attempt));
          continue;
        }
        throw new Error(`GitHub operational JSON write failed for ${relative}: ${response.status}${detail ? ` ${detail}` : ''}`);
      }
      try {
        await verifyGitHubJsonDocument(relative, content, `Operational JSON partition ${relative}`);
        completed = true;
        verified++;
      } catch (error) {
        lastError = error;
        if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 200 * attempt));
      }
    }
    if (!completed) {
      throw new Error(`Operational JSON partition persistence could not be verified for ${relative}${lastError ? `: ${lastError.message}` : '.'}`);
    }
  }
  if (pendingNeedsPersist) await persistPendingState(pendingState);
  return { uploaded: iterations, verified };
}

async function listRemoteOperationalJsonFiles() {
  if (!githubConfig()) return [];
  const files = [];
  const visited = new Set();
  async function walk(relative) {
    if (visited.has(relative)) return;
    visited.add(relative);
    const entries = await githubListDirectory(relative);
    for (const entry of entries) {
      const name = safeString(entry?.name).trim();
      if (!name || name === '.' || name === '..') continue;
      const child = `${relative}/${name}`;
      if (entry.type === 'dir') await walk(child);
      else if (entry.type === 'file' && /^\d{4}\.json\.enc$/.test(name)) files.push(child);
    }
  }
  await walk('operational-json');
  return [...new Set(files)];
}

function entityFromOperationalJsonPath(relative) {
  const parts = String(relative || '').split('/');
  if (parts.length !== 5 || parts[0] !== 'operational-json') return '';
  const entity = parts[1];
  if (!NON_EMPLOYEE_KEYS.includes(entity)) return '';
  if (!/^\d{4}$/.test(parts[2]) || !/^\d{2}$/.test(parts[3]) || !/^\d{4}\.json\.enc$/.test(parts[4])) return '';
  return entity;
}

// Reconcile local JSON partitions with their GitHub mirror on startup. Remote
// records are merged by unique ID using the existing timestamp-aware rules;
// records are then repartitioned by their actual record date. Stale partition
// copies (for example after a historical date edit) are rewritten as empty or
// current buckets instead of being reintroduced on the next restart.
async function restoreOperationalJsonFromGitHubIfNeeded() {
  if (!githubConfig()) return { restored: 0, uploaded: 0 };
  const remoteFiles = await listRemoteOperationalJsonFiles();
  const remoteContents = new Map();
  const remoteByEntity = new Map(NON_EMPLOYEE_KEYS.map(entity => [entity, new Map()]));

  for (const relative of remoteFiles) {
    const entity = entityFromOperationalJsonPath(relative);
    if (!entity) continue;
    const remote = await githubReadFile(relative);
    if (remote?.content == null) continue;
    let parsed;
    try {
      parsed = JSON.parse(decryptText(remote.content));
    } catch (error) {
      throw new Error(`GitHub operational JSON partition is unreadable (${relative}): ${error.message}`);
    }
    if (!Array.isArray(parsed)) throw new Error(`GitHub operational JSON partition is not an array (${relative}).`);
    remoteContents.set(relative, remote.content);
    const byId = remoteByEntity.get(entity);
    for (const record of parsed) {
      if (!record || typeof record !== 'object') continue;
      const normalized = { ...record };
      // Do not discard legacy remote rows just because they predate record IDs.
      // The deterministic ID is persisted back into the correct partition below.
      if (!recordId(normalized)) normalized.id = deterministicLegacyRecordId(entity, normalized);
      const id = recordId(normalized);
      const old = byId.get(id);
      byId.set(id, old
        ? mergeOperationalSnapshot(entity, old, normalized)
        : normalizeIsDeleted(normalized));
    }
  }

  const finalByEntity = new Map();
  const allEntities = new Set([...NON_EMPLOYEE_KEYS]);
  for (const entity of allEntities) {
    const localById = new Map();
    for (const file of listJsonPartitionFiles(entity)) {
      for (const record of readJsonPartition(file)) {
        const id = recordId(record);
        if (id) localById.set(id, record);
      }
    }
    const combined = new Map(remoteByEntity.get(entity) || []);
    for (const [id, localRecord] of localById) {
      const remoteRecord = combined.get(id);
      combined.set(id, remoteRecord
        ? mergeOperationalSnapshot(entity, remoteRecord, localRecord)
        : { ...localRecord });
    }
    const records = [...combined.values()];
    finalByEntity.set(entity, records);
    entityAllJsonCache.delete(entity);
    writeEntityAllToJson(entity, records, true);
  }

  // Ensure every remote/local partition has exactly the records whose current
  // date and ID hash map to that path. This also clears stale remote buckets.
  const allPaths = new Set(remoteFiles);
  for (const entity of allEntities) {
    for (const file of listJsonPartitionFiles(entity)) {
      allPaths.add(path.relative(CSV_ROOT, file).split(path.sep).join('/'));
    }
  }
  const toUpload = new Set();
  for (const relative of allPaths) {
    const entity = entityFromOperationalJsonPath(relative);
    if (!entity) continue;
    const file = path.join(CSV_ROOT, ...relative.split('/'));
    const expected = (finalByEntity.get(entity) || []).filter(record => jsonPartitionForRecord(entity, record) === file);
    writeJsonPartition(file, expected);
    const localContent = fs.readFileSync(file, 'utf8');
    const remoteContent = remoteContents.get(relative);
    if (remoteContent == null || !sameStoredContent(remoteContent, localContent)) toUpload.add(file);
  }
  // Include any partition created while repartitioning records.
  for (const entity of allEntities) {
    entityAllJsonCache.set(entity, (finalByEntity.get(entity) || []).map(record => ({ ...record })));
    for (const file of listJsonPartitionFiles(entity)) {
      const relative = path.relative(CSV_ROOT, file).split(path.sep).join('/');
      if (!remoteContents.has(relative)) toUpload.add(file);
    }
  }
  let uploaded = 0;
  const uploadByEntity = new Map();
  for (const file of toUpload) {
    const relative = path.relative(CSV_ROOT, file).split(path.sep).join('/');
    const entity = entityFromOperationalJsonPath(relative);
    if (!entity) continue;
    if (!uploadByEntity.has(entity)) uploadByEntity.set(entity, []);
    uploadByEntity.get(entity).push(file);
  }
  for (const [entity, files] of uploadByEntity) {
    const result = await syncOperationalJsonPartitionsToGitHub(entity, files);
    uploaded += result.verified;
  }
  return { restored: remoteFiles.length, uploaded };
}

async function rebuildIndexFromRestoredCsv() {
  const rows = [];
  for (const month of getAllLocalMonthlyFiles()) {
    const file = monthlyFile(month);
    if (!fs.existsSync(file)) continue;
    for (const row of readCsvFile(file)) {
      if (!row?.entity || !row?.id) continue;
      rows.push({
        entity: row.entity,
        id: row.id,
        month: row.month || month,
        financial_year: row.financial_year || fyFor(row.date || `${month}-01`),
        updated_at: row.updated_at || new Date().toISOString()
      });
    }
  }
  const unique = new Map();
  for (const row of rows) unique.set(`${row.entity}:${row.id}`, row);
  saveIndex([...unique.values()]);
}

function getAllLocalMonthlyFiles() {
  ensureCsvDirs();
  return fs.readdirSync(MONTHLY_DIR)
    .filter(name => /^\d{4}-\d{2}\.csv$/.test(name))
    .map(name => name.slice(0, 7));
}

async function restoreCsvFromGitHubIfNeeded() {
  if (!githubConfig()) return;

  ensureCsvDirs();

  // The index is derived metadata. Restore it when available, but never rely
  // on it as the sole source of which monthly/FY files exist. A failed index
  // update must not make a valid monthly file invisible after a restart.
  const remoteIndex = await githubReadFile('_index.csv');
  if (remoteIndex?.content != null) {
    const localIndex = fs.existsSync(INDEX_FILE) ? fs.readFileSync(INDEX_FILE, 'utf8') : '';
    if (!localIndex || localIndex !== remoteIndex.content) fs.writeFileSync(INDEX_FILE, remoteIndex.content, 'utf8');
  }

  const months = new Set(loadIndex().map(row => row.month).filter(Boolean));
  const financialYears = new Set(loadIndex().map(row => row.financial_year).filter(Boolean));

  // Always union the remote directory listings with the index. This catches
  // newly-created months/FYs whose index row was not committed yet.
  const remoteMonthly = await githubListDirectory('monthly');
  for (const item of remoteMonthly) {
    const match = safeString(item.name).match(/^(\d{4}-\d{2})\.csv$/);
    if (match) months.add(match[1]);
  }

  const remoteFy = await githubListDirectory('financial-years');
  for (const item of remoteFy) {
    const match = safeString(item.name).match(/^(\d{4}-\d{4})\.csv$/);
    if (match) financialYears.add(match[1]);
  }

  for (const month of months) {
    const remote = await githubReadFile(`monthly/${month}.csv`);
    if (remote?.content != null) {
      const file = monthlyFile(month);
      const localExists = fs.existsSync(file);
      if (!localExists) {
        // First deployment on a new instance: the remote CSV is the only
        // durable source available locally, so restore it exactly.
        fs.writeFileSync(file, remote.content, 'utf8');
      } else {
        // Never replace a valid local transaction history with a stale, empty,
        // or partially synchronized remote snapshot. Merge by entity+record ID
        // and keep the newer version of each record. This is especially
        // important for Inwards/Outwards because older records may predate
        // recently added optional fields.
        const localRows = readCsvFile(file);
        const remoteRows = parseCsv(decryptText(remote.content));
        const mergedRows = mergeRowsByEntityId(localRows, remoteRows);
        // writeCsvFile compares decrypted/plaintext content before writing,
        // so this remains a true no-op when both sources contain the same data.
        writeCsvFile(file, CSV_HEADERS, mergedRows);
      }
    }
  }

  for (const fy of financialYears) {
    const remote = await githubReadFile(`financial-years/${fy}.csv`);
    if (remote?.content != null) {
      const file = financialYearFile(fy);
      const local = fs.existsSync(file) ? readCsvFile(file) : [];
      const remoteRows = parseCsv(decryptText(remote.content));
      const mergedRows = local.length ? mergeRowsByEntityId(local, remoteRows) : remoteRows;
      // Financial-year files are historical backups/lookup data. Merge them
      // by entity + record ID so a stale remote snapshot can never erase a
      // newer local record during restart recovery.
      writeCsvFile(file, CSV_HEADERS, mergedRows);
    }
  }

  // Rebuild the derived index from the restored monthly files so stale or
  // incomplete index metadata can never hide persisted historical records.
  invalidateEntityCsvCache();
  await rebuildIndexFromRestoredCsv();
}

function validateEmployeeIds(employees) {
  const seen = new Set();
  for (const employee of Array.isArray(employees) ? employees : []) {
    const id = employeeIdOf(employee);
    if (!id) throw new Error('Employee ID is required for every employee.');
    if (seen.has(id)) throw new Error(`Duplicate Employee ID: ${id}`);
    seen.add(id);
  }
}

function nextEmployeeIdFromRecords(records) {
  const usedIds = new Set();
  let highest = 0n;
  for (const employee of Array.isArray(records) ? records : []) {
    const id = employeeIdOf(employee);
    if (!id) continue;
    usedIds.add(id);
    if (/^\d+$/.test(id)) {
      try { const n = BigInt(id); if (n > highest) highest = n; } catch (_) {}
    }
  }
  let candidate = highest + 1n;
  while (usedIds.has(candidate.toString())) candidate += 1n;
  return candidate.toString();
}

async function createEmployeeServerSide(details) {
  const latestEmployees = await getEmployeesFromStore(true);
  if (details.pinHash && latestEmployees.some(e => safeString(e.pinHash).trim() === safeString(details.pinHash).trim() && !isDeleted(e))) {
    throw Object.assign(new Error('This PIN is already assigned to another employee.'), { statusCode: 409 });
  }
  const generatedId = nextEmployeeIdFromRecords(latestEmployees);
  const newEmployee = { ...details, id: generatedId, employeeId: generatedId, isDeleted: false, active: true };
  const updatedEmployees = [...latestEmployees, newEmployee];
  validateEmployeeIds(updatedEmployees);
  await writeEmployeeJsonToGitHub(updatedEmployees);
  return { employee: employeePublicView(newEmployee), employees: publicEmployees(updatedEmployees) };
}

async function updateEmployeeServerSide(id, body) {
  const employees = await getEmployeesFromStore(true);
  const index = employees.findIndex(e => employeeIdOf(e) === id);
  if (index === -1) throw Object.assign(new Error('Employee not found.'), { statusCode: 404 });

  const current = employees[index];
  if (body?.pinHash && employees.some((e, i) => i !== index && !isDeleted(e) && safeString(e.pinHash).trim() === safeString(body.pinHash).trim())) {
    throw Object.assign(new Error('This PIN is already assigned to another employee.'), { statusCode: 409 });
  }
  const updated = { ...current, ...body, id, employeeId: id };
  updated.loginRole = employeeRoleOf(updated);
  /* Empty PIN hash from an older frontend must never erase an existing PIN. */
  if (!body?.pinHash) updated.pinHash = current.pinHash || '';
  employees[index] = normalizeIsDeleted(updated);
  validateEmployeeIds(employees);
  await writeEmployeeJsonToGitHub(employees);
  return { employee: employeePublicView(employees[index]), employees: publicEmployees(employees) };
}

/* ---------------------------------------------------------
 * Controlled durable synchronization
 * --------------------------------------------------------- */

function recordSyncTimestamp(record) {
  // idBackfilledAt is migration metadata, not a replacement for the record's
  // business updatedAt timestamp. It lets an ID-only backfill survive merging
  // against a stale remote snapshot while preserving every existing field.
  const values = [record?.idBackfilledAt, record?.updatedAt, record?.updated_at, record?.createdAt, record?.created_at]
    .map(value => Date.parse(safeString(value).trim()))
    .filter(Number.isFinite);
  return values.length ? Math.max(...values) : 0;
}

function mergeAttendanceRecord(first, second) {
  const oldRecord = first && typeof first === 'object' ? first : {};
  const incomingRecord = second && typeof second === 'object' ? second : {};
  const merged = normalizeIsDeleted({ ...oldRecord, ...incomingRecord });

  // A missing property means a partial update; an explicit blank/null means
  // the Admin intentionally cleared that time.
  for (const field of ['inTime', 'outTime']) {
    if (Object.prototype.hasOwnProperty.call(incomingRecord, field)) {
      const value = incomingRecord[field];
      merged[field] = value == null || safeString(value).trim() === '' ? null : safeString(value).trim();
    } else if (Object.prototype.hasOwnProperty.call(oldRecord, field)) {
      merged[field] = oldRecord[field];
    }
  }

  return merged;
}

function mergeRecordsSafely(entity, first, second) {
  if (!first) return second ? { ...second } : null;
  if (!second) return { ...first };
  const aTime = recordSyncTimestamp(first);
  const bTime = recordSyncTimestamp(second);
  let newer = first;
  let older = second;
  if (bTime > aTime) {
    newer = second;
    older = first;
  }
  const merged = entity === 'fl_workorders'
    ? mergeEntityRecord(entity, older, newer)
    : entity === 'fl_attendance'
      ? mergeAttendanceRecord(older, newer)
      : normalizeIsDeleted({ ...older, ...newer });
  // Explicit deletion from the newer version must never be lost.
  if (recordSyncTimestamp(newer) >= recordSyncTimestamp(older) && isDeleted(newer)) merged.isDeleted = true;
  return merged;
}

function mergeOperationalSnapshot(entity, first, second) {
  const merged = mergeRecordsSafely(entity, first, second);
  if (entity === 'fl_workorders' && (first?.__replaceWorks === true || second?.__replaceWorks === true)) {
    const replacementSource = second?.__replaceWorks === true ? second : first;
    return {
      ...merged,
      __replaceWorks: true,
      works: (Array.isArray(replacementSource?.works)
        ? replacementSource.works
        : Array.isArray(merged?.works) ? merged.works : []).map(work => ({ ...work }))
    };
  }
  return merged;
}


function dailyJsonMigrationPublicStatus() {
  return {
    date: dailyJsonMigrationStatus.date || appTodayStr(),
    status: dailyJsonMigrationStatus.status || 'idle',
    startedAt: dailyJsonMigrationStatus.startedAt || null,
    completedAt: dailyJsonMigrationStatus.completedAt || null,
    message: dailyJsonMigrationStatus.message || '',
    processedRecords: Number(dailyJsonMigrationStatus.processedRecords || 0),
    verifiedPartitions: Number(dailyJsonMigrationStatus.verifiedPartitions || 0),
    error: dailyJsonMigrationStatus.error || null
  };
}

async function readDailyJsonMigrationControl() {
  if (!githubConfig()) throw new Error('Private GitHub storage is not configured.');
  const remote = await githubReadFile(DAILY_JSON_MIGRATION_CONTROL_PATH);
  if (!remote?.content) return { control: { version: 1, lastCompletedDate: '', status: 'idle' }, sha: null };
  let control;
  try { control = JSON.parse(remote.content); }
  catch (_) { throw new Error('The persistent daily JSON migration control file is invalid JSON.'); }
  if (!control || control.version !== 1) throw new Error('The persistent daily JSON migration control file has an unsupported version.');
  return { control, sha: remote.sha || null };
}

// Writes the persistent migration control document using GitHub's SHA as a
// compare-and-swap token. This prevents two Render instances from acquiring
// the same daily migration lock at the same time.
async function writeDailyJsonMigrationControl(control, expectedSha) {
  const config = githubConfig();
  if (!config) throw new Error('Private GitHub storage is not configured.');
  const body = {
    message: `SOV Engineering daily JSON migration control ${safeString(control.status || 'update')} [skip render]`,
    content: Buffer.from(JSON.stringify(control, null, 2), 'utf8').toString('base64'),
    branch: config.branch
  };
  if (expectedSha) body.sha = expectedSha;
  const response = await githubRequest(`${config.basePath}/${DAILY_JSON_MIGRATION_CONTROL_PATH}`, {
    method: 'PUT', body: JSON.stringify(body)
  });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    const error = new Error(`Daily JSON migration control update failed: ${response.status}${detail ? ` ${detail}` : ''}`);
    error.status = response.status;
    throw error;
  }
  let responseBody = {};
  try { responseBody = await response.json(); } catch (_) {}
  let lastReadError = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const verified = await githubReadFile(DAILY_JSON_MIGRATION_CONTROL_PATH);
      if (verified?.content) {
        let parsed;
        try { parsed = JSON.parse(verified.content); } catch (_) { parsed = null; }
        if (parsed && sameJsonValue(parsed, control)) {
          dailyJsonMigrationStatusCache = { checkedAt: Date.now(), control: parsed };
          return { control: parsed, sha: verified.sha || responseBody?.content?.sha || null };
        }
      }
      lastReadError = new Error('GitHub returned a previous or mismatched daily migration control version.');
    } catch (error) { lastReadError = error; }
    if (attempt < 4) await new Promise(resolve => setTimeout(resolve, 200 * (attempt + 1)));
  }
  throw new Error(`Daily JSON migration control read-back verification failed${lastReadError ? `: ${lastReadError.message}` : '.'}`);
}

async function acquireDailyJsonMigrationLock(today) {
  const remote = await readDailyJsonMigrationControl();
  const old = remote.control || {};
  if (safeString(old.lastCompletedDate) === today) return { acquired: false, completed: true, control: old };
  const now = Date.now();
  if (safeString(old.status) === 'running' && Number(old.lockExpiresAt || 0) > now) {
    return { acquired: false, running: true, control: old };
  }
  const lockOwner = crypto.randomUUID();
  const next = {
    version: 1,
    lastCompletedDate: safeString(old.lastCompletedDate),
    status: 'running',
    lastAttemptDate: today,
    startedAt: new Date().toISOString(),
    completedAt: safeString(old.completedAt) || null,
    lockOwner,
    lockExpiresAt: now + DAILY_JSON_MIGRATION_LOCK_MS,
    processedRecords: 0,
    verifiedPartitions: 0,
    error: null
  };
  try {
    const written = await writeDailyJsonMigrationControl(next, remote.sha);
    return { acquired: true, owner: lockOwner, control: written.control, sha: written.sha };
  } catch (error) {
    if (error.status === 409 || error.status === 422) return { acquired: false, running: true, control: old };
    throw error;
  }
}

async function loadPendingStateForDailyJsonMigration() {
  if (!githubConfig()) throw new Error('Private GitHub storage is not configured; migration cannot be safely verified.');
  // Read GitHub directly and fail closed on remote errors. The general pending
  // loader is intentionally best-effort for page reads, but a migration must
  // never mark completion based only on Render's temporary local filesystem.
  const remote = await githubReadFile(PREVIOUS_PENDING_JSON_GITHUB);
  const local = fs.existsSync(PREVIOUS_PENDING_JSON_LOCAL) ? readDailyJsonFile(PREVIOUS_PENDING_JSON_LOCAL) : null;
  const localState = normalizePendingState(local);
  let remoteState = emptyPendingState();
  if (remote?.content) {
    try { remoteState = normalizePendingState(JSON.parse(decryptText(remote.content))); }
    catch (error) { throw new Error(`Persistent Previous/Pending JSON could not be decrypted or parsed: ${error.message}`); }
  }
  const merged = mergePendingStates(localState, remoteState);
  // If an older deployment left useful data only on the local disk, promote
  // the merged recovery buffer to GitHub and verify it before migration. This
  // prevents the daily job from relying on Render's ephemeral copy alone.
  if (!sameJsonValue(merged.entities, remoteState.entities)) await persistPendingState(merged);
  else { pendingState = merged; pendingStateLoaded = true; }
  return normalizePendingState(pendingState);
}

function resolveLegacyPendingIds(entity, pendingRecords, existingRecords) {
  const existing = Array.isArray(existingRecords) ? existingRecords : [];
  const stableIndex = new Map();
  for (const record of existing) {
    const key = legacyStableIdentityKey(entity, record);
    const id = recordId(record);
    if (!key || !id) continue;
    const list = stableIndex.get(key) || [];
    list.push(record);
    stableIndex.set(key, list);
  }
  return (Array.isArray(pendingRecords) ? pendingRecords : []).map(record => {
    if (!record?.__legacyIdGenerated) return { ...record };
    const exactIdMatch = existing.find(candidate => recordId(candidate) === recordId(record));
    if (exactIdMatch) {
      const resolved = { ...record, id: recordId(exactIdMatch) };
      delete resolved.__legacyIdGenerated;
      return resolved;
    }
    const key = legacyStableIdentityKey(entity, record);
    if (!key) throw new Error(`Legacy ${entity} record has no stable ID and no reliable match key. It remains in Pending JSON for safe manual resolution.`);
    const matches = stableIndex.get(key) || [];
    if (matches.length > 1) throw new Error(`Legacy ${entity} record has an ambiguous stable match (${matches.length} records). It remains in Pending JSON for safe manual resolution.`);
    if (matches.length === 1) {
      const resolved = { ...record, id: recordId(matches[0]) };
      delete resolved.__legacyIdGenerated;
      return resolved;
    }
    // No existing match: keep the deterministic ID, which remains stable on
    // retries, and remove the transient recovery marker before it enters the
    // operational data model.
    const created = { ...record };
    delete created.__legacyIdGenerated;
    return created;
  });
}

async function performDailyJsonYearwiseMigration(today, renewLock) {
  return enqueueDurableCsvWrite(async () => {
    const pending = await loadPendingStateForDailyJsonMigration();
    // Preserve the original CSV sync obligation before the migration is allowed
    // to remove successfully verified records from Previous/Pending.
    const csvQueue = await loadPersistentCsvSyncPendingState();
    await persistCsvSyncPendingState(mergePendingStates(csvQueue, pending));
    const sourceByEntity = new Map(NON_EMPLOYEE_KEYS.map(entity => [entity, new Map()]));
    for (const entity of NON_EMPLOYEE_KEYS) {
      const existing = loadEntityAllFromJson(entity);
      pending.entities[entity] = resolveLegacyPendingIds(entity, pending.entities[entity], existing);
    }
    await persistPendingState(pending);

    // The current daily working layer is also a source when it is already
    // loaded for this business date. Do not rebuild it from CSV here: that
    // would turn a daily migration into a historical CSV scan on login.
    if (dailyStateLoaded && dailyState?.date === today) {
      for (const entity of NON_EMPLOYEE_KEYS) {
        for (const record of Array.isArray(dailyState.entities?.[entity]) ? dailyState.entities[entity] : []) {
          const id = recordId(record);
          if (id) sourceByEntity.get(entity).set(id, { ...record });
        }
      }
    }
    // Previous/Pending holds unsynchronized records across dates. Include all
    // of them so missed login days are recovered on the next eligible login.
    for (const entity of NON_EMPLOYEE_KEYS) {
      const target = sourceByEntity.get(entity);
      for (const record of Array.isArray(pending.entities?.[entity]) ? pending.entities[entity] : []) {
        const id = recordId(record);
        if (!id) continue;
        const old = target.get(id);
        target.set(id, old ? mergeOperationalSnapshot(entity, old, record) : { ...record });
      }
    }

    let processedRecords = 0;
    let verifiedPartitions = 0;
    for (const entity of NON_EMPLOYEE_KEYS) {
      if (typeof renewLock === 'function') await renewLock();
      const source = [...sourceByEntity.get(entity).values()];
      if (!source.length) continue;
      const current = loadEntityAllFromJson(entity);
      const byId = new Map(current.map(record => [recordId(record), { ...record }]));
      const needsPersistence = new Set();
      for (const incoming of source) {
        const id = recordId(incoming);
        if (!id) continue;
        const old = byId.get(id);
        const merged = old ? mergeOperationalSnapshot(entity, old, incoming) : { ...incoming };
        if (!old || !sameJsonValue(normalizeIsDeleted(old), normalizeIsDeleted(merged))) needsPersistence.add(id);
        byId.set(id, merged);
      }
      const mergedRecords = [...byId.values()];
      const write = writeEntityAllToJson(entity, mergedRecords);
      const files = new Set(write.changedFiles || []);
      // Only force remote verification for partitions containing records that
      // were missing or changed. Already-verified, unchanged records do not
      // cause a redundant GitHub write/read cycle on this daily pass.
      for (const id of needsPersistence) {
        const finalRecord = byId.get(id);
        if (!finalRecord) throw new Error(`Missing merged ${entity} record ${id}.`);
        files.add(jsonPartitionForRecord(entity, finalRecord));
      }
      const synced = files.size ? await syncOperationalJsonPartitionsToGitHub(entity, [...files]) : { verified: 0 };
      verifiedPartitions += Number(synced.verified || 0);
      // The mirror reconciliation can discover a newer remote version and
      // update the cache. Verify against that final timestamp-aware winner, not
      // the pre-sync snapshot, so newer data is preserved rather than falsely
      // reported as a mismatch or overwritten by an older pending record.
      for (const latest of (entityAllJsonCache.get(entity) || [])) {
        const id = recordId(latest);
        if (id) byId.set(id, { ...latest });
      }

      const verifiedByPath = new Map();
      for (const file of files) {
        const rows = fs.existsSync(file) ? readJsonPartition(file) : [];
        verifiedByPath.set(file, new Map(rows.map(record => [recordId(record), record])));
      }
      for (const incoming of source) {
        const id = recordId(incoming);
        const finalRecord = byId.get(id);
        if (!id || !finalRecord) throw new Error(`Missing merged ${entity} record ${id || '(unknown ID)'}.`);
        const targetFile = jsonPartitionForRecord(entity, finalRecord);
        let stored = verifiedByPath.get(targetFile)?.get(id);
        if (!stored && fs.existsSync(targetFile)) stored = readJsonPartition(targetFile).find(record => recordId(record) === id);
        if (!stored) throw new Error(`Year-wise JSON verification failed for ${entity}/${id}: destination record is missing.`);
        if (jsonPartitionForRecord(entity, stored) !== targetFile) throw new Error(`Year-wise JSON date partition verification failed for ${entity}/${id}.`);
        if (!sameJsonValue(normalizeIsDeleted(stored), normalizeIsDeleted(finalRecord))) {
          throw new Error(`Year-wise JSON verification failed for ${entity}/${id}: saved record differs from the intended merged version.`);
        }
        processedRecords++;
      }
      // Remove only this entity's records after every destination partition and
      // record in the entity has been verified. If a later entity fails, earlier
      // verified work is safely absent from Previous/Pending but remains in the
      // separate CSV-sync journal; unprocessed entities remain pending.
      const processedIds = new Set(source.map(recordId).filter(Boolean));
      if (processedIds.size) {
        const refreshed = normalizePendingState(pendingState);
        refreshed.entities[entity] = (refreshed.entities[entity] || []).filter(record => !processedIds.has(recordId(record)));
        await persistPendingState(refreshed);
        pending.entities[entity] = refreshed.entities[entity];
      }
    }
    return { processedRecords, verifiedPartitions };
  });
}

async function startDailyJsonYearwiseMigration() {
  const today = appTodayStr();
  if (dailyJsonMigrationPromise) {
    if (dailyJsonMigrationStatus.date === today) return dailyJsonMigrationPromise;
    // If a previous business day's run is still finishing across midnight,
    // queue today's eligible run behind it so the first Admin login today is
    // still the trigger without overlapping two migration transactions.
    const previousRun = dailyJsonMigrationPromise;
    return previousRun.catch(() => null).then(() => startDailyJsonYearwiseMigration());
  }
  if (dailyJsonMigrationStatus.date === today && dailyJsonMigrationStatus.status === 'complete') return dailyJsonMigrationPublicStatus();

  dailyJsonMigrationStatus = { date: today, status: 'checking', startedAt: null, completedAt: null, message: 'Checking persistent daily migration status.' };
  dailyJsonMigrationPromise = (async () => {
    let lock = null;
    try {
      lock = await acquireDailyJsonMigrationLock(today);
      if (!lock.acquired) {
        if (lock.completed) {
          dailyJsonMigrationStatus = { date: today, status: 'complete', startedAt: null, completedAt: lock.control.completedAt || null, message: 'Daily JSON synchronization was already completed for this business date.', processedRecords: Number(lock.control.processedRecords || 0), verifiedPartitions: Number(lock.control.verifiedPartitions || 0) };
        } else {
          dailyJsonMigrationStatus = { date: today, status: 'running', startedAt: lock.control.startedAt || null, completedAt: null, message: 'Daily JSON synchronization is already running on another server instance.' };
        }
        return dailyJsonMigrationPublicStatus();
      }
      dailyJsonMigrationStatus = { date: today, status: 'running', startedAt: lock.control.startedAt, completedAt: null, message: 'Synchronizing daily and pending JSON records into verified year-wise JSON partitions.' };
      const result = await performDailyJsonYearwiseMigration(today, async () => {
        if (Number(lock.control.lockExpiresAt || 0) - Date.now() > 120000) return;
        const renewedControl = { ...lock.control, lockExpiresAt: Date.now() + DAILY_JSON_MIGRATION_LOCK_MS };
        const renewed = await writeDailyJsonMigrationControl(renewedControl, lock.sha);
        lock.control = renewed.control;
        lock.sha = renewed.sha;
      });
      const finishedAt = new Date().toISOString();
      const completed = {
        ...lock.control,
        version: 1,
        lastCompletedDate: today,
        status: 'complete',
        completedAt: finishedAt,
        lockOwner: '',
        lockExpiresAt: 0,
        processedRecords: result.processedRecords,
        verifiedPartitions: result.verifiedPartitions,
        error: null
      };
      await writeDailyJsonMigrationControl(completed, lock.sha);
      dailyJsonMigrationStatus = { date: today, status: 'complete', startedAt: lock.control.startedAt, completedAt: finishedAt, message: `Daily JSON synchronization completed and verified. ${result.processedRecords} records checked.`, processedRecords: result.processedRecords, verifiedPartitions: result.verifiedPartitions };
      console.info(`[Daily JSON migration] date=${today} status=complete records=${result.processedRecords} verifiedPartitions=${result.verifiedPartitions}`);
      return dailyJsonMigrationPublicStatus();
    } catch (error) {
      const detail = safeString(error?.message || error || 'Unknown daily migration error').slice(0, 800);
      dailyJsonMigrationStatus = { date: today, status: 'failed', startedAt: dailyJsonMigrationStatus.startedAt || null, completedAt: null, message: 'Daily JSON synchronization failed. Unprocessed records remain in Previous/Pending; verified records remain in year-wise JSON and the CSV-sync journal. It can retry on the next successful Admin login.', error: detail };
      console.error(`[Daily JSON migration] date=${today} status=failed`, detail);
      // Release the lock when possible. The lease is a fallback if GitHub is
      // unavailable, and lastCompletedDate remains unchanged so the next Admin
      // login can retry safely.
      try {
        const latest = await readDailyJsonMigrationControl();
        if (lock?.owner && latest.control?.lockOwner === lock.owner) {
          const failed = { ...latest.control, status: 'failed', lockOwner: '', lockExpiresAt: 0, failedAt: new Date().toISOString(), error: detail };
          await writeDailyJsonMigrationControl(failed, latest.sha);
        }
      } catch (releaseError) {
        console.error('Could not release daily JSON migration lock; it will expire automatically:', releaseError.message);
      }
      return dailyJsonMigrationPublicStatus();
    } finally {
      dailyJsonMigrationPromise = null;
    }
  })();
  return dailyJsonMigrationPromise;
}

async function getDailyJsonMigrationStatusForAdmin() {
  const today = appTodayStr();
  if (dailyJsonMigrationStatus.date === today && (['failed', 'complete'].includes(dailyJsonMigrationStatus.status) || (dailyJsonMigrationPromise && ['running', 'checking'].includes(dailyJsonMigrationStatus.status)))) return dailyJsonMigrationPublicStatus();
  const summarize = control => {
    let status = 'idle';
    if (safeString(control.lastCompletedDate) === today) status = 'complete';
    else if (safeString(control.lastAttemptDate) === today && safeString(control.status) === 'failed') status = 'failed';
    else if (safeString(control.status) === 'running' && Number(control.lockExpiresAt || 0) > Date.now()) status = 'running';
    return { date: today, status, startedAt: control.startedAt || null, completedAt: control.completedAt || null, message: status === 'complete' ? 'Daily JSON synchronization already completed for this business date.' : status === 'failed' ? 'Daily JSON synchronization failed and will retry on the next successful Admin login.' : status === 'running' ? 'Daily JSON synchronization is running on a server instance.' : 'Daily JSON synchronization will start after a successful Admin login.', processedRecords: Number(control.processedRecords || 0), verifiedPartitions: Number(control.verifiedPartitions || 0), error: control.error || null };
  };
  if (Date.now() - dailyJsonMigrationStatusCache.checkedAt < 10000 && dailyJsonMigrationStatusCache.control) return summarize(dailyJsonMigrationStatusCache.control);
  try {
    const { control } = await readDailyJsonMigrationControl();
    dailyJsonMigrationStatusCache = { checkedAt: Date.now(), control };
    return summarize(control);
  } catch (error) {
    return { date: today, status: 'unavailable', startedAt: null, completedAt: null, message: 'Persistent migration status could not be checked.', error: safeString(error.message || error) };
  }
}

function mergeRowsByEntityId(localRows, remoteRows) {
  const map = new Map();
  for (const row of Array.isArray(localRows) ? localRows : []) {
    if (!row?.entity || !row?.id) continue;
    map.set(`${row.entity}:${row.id}`, { ...row });
  }
  for (const row of Array.isArray(remoteRows) ? remoteRows : []) {
    if (!row?.entity || !row?.id) continue;
    const key = `${row.entity}:${row.id}`;
    const local = map.get(key);
    if (!local) {
      map.set(key, { ...row });
      continue;
    }
    let localRecord = null;
    let remoteRecord = null;
    try { localRecord = JSON.parse(local.payload || '{}'); } catch (_) {}
    try { remoteRecord = JSON.parse(row.payload || '{}'); } catch (_) {}
    const merged = mergeRecordsSafely(row.entity, localRecord, remoteRecord);
    map.set(key, {
      ...local,
      ...row,
      date: recordDate(row.entity, merged),
      financial_year: fyFor(recordDate(row.entity, merged)),
      updated_at: safeString(merged?.updatedAt || merged?.updated_at || row.updated_at || local.updated_at || new Date().toISOString()),
      payload: JSON.stringify(merged || {})
    });
  }
  return [...map.values()];
}

function gitBlobSha(content) {
  const body = Buffer.from(String(content), 'utf8');
  return crypto.createHash('sha1').update(`blob ${body.length}\0`).update(body).digest('hex');
}

async function mergeRemoteCsvIntoLocalSafely() {
  if (!githubConfig()) return;
  const remoteMonthly = await githubListDirectory('monthly');
  for (const item of remoteMonthly) {
    const match = safeString(item.name).match(/^(\d{4}-\d{2})\.csv$/);
    if (!match) continue;
    const month = match[1];
    const localFile = monthlyFile(month);
    if (item.sha && fs.existsSync(localFile)) {
      const localContent = fs.readFileSync(localFile, 'utf8');
      if (gitBlobSha(localContent) === item.sha) continue;
    }
    const remote = await githubReadFile(`monthly/${month}.csv`);
    if (!remote?.content) continue;
    const remoteRows = parseCsv(decryptText(remote.content));
    const localRows = readCsvFile(monthlyFile(month));
    const merged = mergeRowsByEntityId(localRows, remoteRows);
    writeCsvFile(monthlyFile(month), CSV_HEADERS, merged);
  }
  invalidateEntityCsvCache();
  await rebuildIndexFromRestoredCsv();
}

function buildDailyStateFromCsv(date) {
  const out = emptyDailyState(date);
  const month = monthFor(date);
  for (const entity of NON_EMPLOYEE_KEYS) {
    const rows = readEntityMonth(entity, month)
      .map(record => normalizeIsDeleted({ ...record }))
      .filter(record => !isDeleted(record) && recordDate(entity, record) === date);
    out.entities[entity] = rows;
  }
  return out;
}

async function loadAllPendingDailyStates() {
  const state = pendingStateLoaded
    ? normalizePendingState(pendingState)
    : await loadPersistentPendingState();

  // Keep the existing caller contract while making the underlying storage a
  // single date-independent Previous/Pending JSON file. Dates remain on the
  // individual records and are used only for CSV month/FY routing and status.
  return [{ date: 'pending', state }];
}

function pendingRecordDiffersFromCsv(entity, record, monthCache, indexById) {
  const id = recordId(record);
  if (!id) return true;
  const candidateMonths = new Set([monthFor(recordDate(entity, record))]);
  const indexed = indexById.get(`${entity}:${id}`);
  if (indexed?.month) candidateMonths.add(indexed.month);
  let csvRecord = null;
  for (const month of candidateMonths) {
    const cacheKey = `${entity}:${month}`;
    let byId = monthCache.get(cacheKey);
    if (!byId) {
      byId = new Map();
      for (const row of readEntityMonth(entity, month)) {
        const rowId = recordId(row);
        if (rowId) byId.set(rowId, normalizeIsDeleted({ ...row }));
      }
      monthCache.set(cacheKey, byId);
    }
    if (byId.has(id)) { csvRecord = byId.get(id); break; }
  }
  if (!csvRecord) return true;
  const merged = entity === 'fl_workorders'
    ? mergeEntityRecord(entity, csvRecord, record)
    : mergeRecordsSafely(entity, csvRecord, record);
  return JSON.stringify(normalizeIsDeleted(merged)) !== JSON.stringify(normalizeIsDeleted(csvRecord));
}

async function getPendingCsvSyncStatus() {
  const queue = await loadPersistentCsvSyncPendingState();
  const primary = pendingStateLoaded ? normalizePendingState(pendingState) : await loadPersistentPendingState();
  const combined = mergePendingStates(queue, primary);
  const index = loadIndex();
  const indexById = new Map(index.filter(row=>row?.entity&&row?.id).map(row=>[`${row.entity}:${row.id}`,row]));
  const monthCache = new Map();
  const pending = [];
  for (const entity of NON_EMPLOYEE_KEYS) {
    for (const record of Array.isArray(combined?.entities?.[entity]) ? combined.entities[entity] : []) {
      if (pendingRecordDiffersFromCsv(entity, record, monthCache, indexById)) {
        pending.push({date:recordDate(entity, record),entity,id:recordId(record)});
      }
    }
  }
  return {
    pending: pending.length>0,
    count: pending.length,
    dates:[...new Set(pending.map(x=>x.date))].sort(),
    entities:[...new Set(pending.map(x=>x.entity))].sort(),
    records: pending
  };
}

async function synchronizeDataOnAdminLogin() {
  const syncStartedAt = Date.now();
  return enqueueDurableCsvWrite(async () => {
    const primaryPending = await loadPersistentPendingState();
    const csvQueue = await loadPersistentCsvSyncPendingState();
    const pending = mergePendingStates(csvQueue, primaryPending);
    // Seed/repair the separate encrypted CSV-sync journal before beginning the
    // CSV transaction. Year-wise migration may already have cleared records
    // from Previous/Pending, but this journal remains until CSV commits verify.
    await persistCsvSyncPendingState(pending);
    const sourceByEntity = new Map(NON_EMPLOYEE_KEYS.map(entity => [entity, new Map()]));

    for (const entity of NON_EMPLOYEE_KEYS) {
      const target = sourceByEntity.get(entity);
      for (const record of Array.isArray(pending.entities?.[entity]) ? pending.entities[entity] : []) {
        const id = recordId(record);
        if (!id) continue;
        const old = target.get(id);
        target.set(id, old
          ? mergeRecordsSafely(entity, old, record)
          : { ...record });
      }
    }

    const status = await getPendingCsvSyncStatus();
    for (const entity of NON_EMPLOYEE_KEYS) {
      const incoming = [...sourceByEntity.get(entity).values()];
      if (!incoming.length) continue;

      try {
        const csvResult = writeEntityRecordsToCsv(entity, incoming);
        const verified = loadEntityAllFromCsv(entity);
        const jsonWrite = writeEntityAllToJson(entity, verified);
        const jsonFilesToSync = new Set(jsonWrite.changedFiles || []);
        for (const record of incoming) {
          const id = recordId(record);
          const saved = verified.find(row => recordId(row) === id) || record;
          jsonFilesToSync.add(jsonPartitionForRecord(entity, saved));
        }
        await syncOperationalJsonPartitionsToGitHub(entity, [...jsonFilesToSync]);
        const expected = new Map(incoming.map(record => [recordId(record), record]));
        for (const [id, record] of expected) {
          const saved = verified.find(row => recordId(row) === id);
          if (!saved) throw new Error(`CSV verification failed for ${entity}/${id}: record was not found after write.`);
          if (recordDate(entity, saved) !== recordDate(entity, record)) {
            throw new Error(`CSV date verification failed for ${entity}/${id}.`);
          }
        }

        const changedMonths = csvResult.changedMonths.length
          ? csvResult.changedMonths
          : [...new Set(incoming.map(record => monthFor(recordDate(entity, record))))];
        const changedFys = [...new Set(changedMonths.map(month => fyFor(`${month}-01`)))];
        await syncCsvFilesToGitHub(entity, verified, {
          months: changedMonths,
          financialYears: changedFys,
          includeIndex: true
        });
      } catch (error) {
        throw new Error(`CSV synchronization failed for ${entity}: ${safeString(error?.message || error)}`);
      }
    }

    // Only after local CSV verification and GitHub CSV synchronization have
    // succeeded do we remove records from the Previous/Pending JSON. Records
    // still differing from CSV remain for the next retry.
    const refreshedPending = normalizePendingState(pending);
    const index = loadIndex();
    const indexById = new Map(index.filter(row => row?.entity && row?.id).map(row => [`${row.entity}:${row.id}`, row]));
    const monthCache = new Map();
    for (const entity of NON_EMPLOYEE_KEYS) {
      refreshedPending.entities[entity] = (pending.entities[entity] || []).filter(record =>
        pendingRecordDiffersFromCsv(entity, record, monthCache, indexById)
      );
    }

    await persistPendingState(refreshedPending);
    // persistPendingState safely journals any remaining changes; now replace the
    // CSV-sync journal with the exact verified remainder so successfully synced
    // records are not replayed indefinitely.
    await persistCsvSyncPendingState(refreshedPending);
    dailyState = await loadCurrentDailyState(appTodayStr());
    dailyStateLoaded = true;

    console.info(`[CSV sync timing] operation=admin-sync durationMs=${Date.now()-syncStartedAt} sourcePending=${status.count} remainingPending=${Object.values(refreshedPending.entities || {}).reduce((sum, list) => sum + list.length, 0)}`);
    return {
      ok: true,
      noOp: status.count === 0,
      pendingCount: status.count
    };
  });
}

/* ---------------------------------------------------------
 * Admin authentication
 * --------------------------------------------------------- */



function getAdminPin() {
  let pin = safeString(process.env.ADMIN_PIN).trim();
  if ((pin.startsWith('"') && pin.endsWith('"')) || (pin.startsWith("'") && pin.endsWith("'"))) {
    pin = pin.slice(1, -1).trim();
  }

  if (!pin) {
    throw new Error(
      'ADMIN_PIN environment variable is missing.'
    );
  }

  return pin;
}

function getCommonDashboardPin() {
  let pin = safeString(process.env.COMMON_DASHBOARD_PIN).trim();
  if ((pin.startsWith('\"') && pin.endsWith('\"')) || (pin.startsWith("'") && pin.endsWith("'"))) pin = pin.slice(1, -1).trim();
  if (!pin) throw new Error('COMMON_DASHBOARD_PIN environment variable is missing.');
  return pin;
}

function verifyCommonDashboardPin(enteredPin) {
  const configured = getCommonDashboardPin();
  const a = crypto.createHash('sha256').update(configured,'utf8').digest();
  const b = crypto.createHash('sha256').update(safeString(enteredPin).trim(),'utf8').digest();
  return crypto.timingSafeEqual(a,b);
}

function verifyAdminPin(
  enteredPin
) {
  const configured =
    getAdminPin();

  const entered =
    safeString(
      enteredPin
    ).trim();

  const configuredHash =
    crypto
      .createHash('sha256')
      .update(
        configured,
        'utf8'
      )
      .digest();

  const enteredHash =
    crypto
      .createHash('sha256')
      .update(
        entered,
        'utf8'
      )
      .digest();

  return crypto.timingSafeEqual(
    configuredHash,
    enteredHash
  );
}

const revokedAuthTokens = new Set();

function authTokenFingerprint(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

function authSecret() {
  const configured = safeString(process.env.SOV_AUTH_SECRET).trim();
  if (configured) return configured;
  return getAdminPin();
}

function createAuthToken(payload) {
  const body = Buffer.from(JSON.stringify({
    ...payload,
    iat: Date.now(),
    exp: Date.now() + 12 * 60 * 60 * 1000
  }), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', authSecret()).update(body).digest('base64url');
  return body + '.' + sig;
}

function readAuthToken(req) {
  const header = safeString(req.headers.authorization);
  const token = /^Bearer\s+/i.test(header) ? header.replace(/^Bearer\s+/i, '').trim() : safeString(req.query?.token).trim();
  if (!token || revokedAuthTokens.has(authTokenFingerprint(token))) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', authSecret()).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!payload || !payload.role || Number(payload.exp || 0) < Date.now()) return null;
    return payload;
  } catch (_) { return null; }
}

function requireAuth(req, res, allowedRoles = []) {
  const auth = readAuthToken(req);
  if (!auth) { res.status(401).json({ok:false,error:'Authentication required.'}); return null; }
  if (allowedRoles.length && !allowedRoles.includes(auth.role)) { res.status(403).json({ok:false,error:'You are not authorized for this action.'}); return null; }
  req.auth = auth;
  return auth;
}

app.post('/api/auth/logout', (req, res) => {
  const header = safeString(req.headers.authorization);
  const token = /^Bearer\s+/i.test(header)
    ? header.replace(/^Bearer\s+/i, '').trim()
    : safeString(req.body?.token || req.query?.token).trim();
  if (token) revokedAuthTokens.add(authTokenFingerprint(token));
  return res.json({ ok: true });
});

function employeeRoleOf(employee) {
  const raw = safeString(employee?.loginRole || employee?.accessRole || employee?.accountType || '').trim().toUpperCase().replace(/[-\s]+/g,'_');
  if (raw === 'ADMIN_WORKER' || raw === 'ADMINANDWORKER' || raw === 'ADMIN_AND_WORKER') return 'ADMIN_WORKER';
  if (raw === 'ADMIN') return 'ADMIN';
  return 'WORKER';
}

function employeeActiveOnDateServer(employee, date = appTodayStr()) {
  if (!employee || isDeleted(employee)) return false;
  const target = safeString(date).slice(0,10);
  const relievingDate = safeString(employee.relievingDate).slice(0,10);
  return !/^\d{4}-\d{2}-\d{2}$/.test(relievingDate) || target < relievingDate;
}

function validateRelievingDateServer(value) {
  const date = safeString(value).trim();
  if (!date) return '';
  const match = date.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  const parsed = match ? new Date(`${date}T00:00:00Z`) : null;
  if (!match || !parsed || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0,10) !== date || date < appTodayStr()) {
    throw Object.assign(new Error('Relieving date must be today or a future date.'), { statusCode:400 });
  }
  return date;
}

function filterRecordsForAuth(key, records, auth) {
  if (!auth || ['main_admin','admin_employee','admin_worker','dashboard'].includes(auth.role)) return records;
  if (auth.role !== 'worker') return [];
  const id = safeString(auth.employeeId);
  const worker = Array.isArray(employeeCache) ? employeeCache.find(employee=>employeeIdOf(employee)===id) : null;
  if (!employeeActiveOnDateServer(worker)) return [];
  if (key === 'fl_employees') return records.filter(x => employeeIdOf(x) === id);
  if (key === 'fl_workorders' || key === 'fl_workhistory') {
    return records.map(job => ({ ...job, works: Array.isArray(job.works) ? job.works.filter(w => assignedIdsServer(w).includes(id)) : [] }))
      .filter(job => Array.isArray(job.works) && job.works.length);
  }
  if (['fl_attendance','fl_permissions','fl_leaves','fl_sundayot','fl_finance'].includes(key)) {
    return records.filter(x => String(x.employeeId || x.workerId || '') === id);
  }
  return [];
}

function assignedIdsServer(work) {
  if (Array.isArray(work?.assignedTo)) return work.assignedTo.map(String);
  return work?.assignedTo ? [String(work.assignedTo)] : [];
}

app.post('/api/auth/admin', async (req, res) => {
  try {
    const employeeCode = safeString(req.body?.employeeCode || req.body?.code).trim();
    const pin = safeString(req.body?.pin).trim();
    if (!pin) return res.status(400).json({ok:false,error:'Admin PIN is required.'});
    if (employeeCode) {
      const employees = await getEmployeesFromStore(true);
      const employee = employees.find(e => employeeActiveOnDateServer(e) && employeeCodeOf(e) === employeeCode && ['ADMIN','ADMIN_WORKER'].includes(employeeRoleOf(e)));
      if (!employee) return res.status(401).json({ok:false,error:'Admin Employee Code not found or this employee is not an Admin.'});
      const configuredHash = safeString(employee.pinHash).trim();
      const enteredHash = crypto.createHash('sha256').update(pin,'utf8').digest('hex');
      const a=Buffer.from(configuredHash,'utf8'), b=Buffer.from(enteredHash,'utf8');
      if (!configuredHash || a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({ok:false,error:'Incorrect PIN.'});
      const loginRole = employeeRoleOf(employee)==='ADMIN_WORKER' ? 'admin_worker' : 'admin_employee';
      res.json({ok:true,worker:employeePublicView(employee),role:loginRole,token:createAuthToken({role:loginRole,employeeId:employeeIdOf(employee)})});
      return;
    }
    if (!verifyAdminPin(pin)) return res.status(401).json({ok:false,error:'Incorrect PIN.'});
    res.json({ok:true,token:createAuthToken({role:'main_admin'})});
    return;
  } catch (error) {
    console.error('Admin authentication configuration error.');
    return res.status(503).json({ok:false,error:'Admin authentication is not configured.'});
  }
});

app.use(['/api/admin/daily-json-migration-status','/api/admin/csv-pending-check','/api/admin/json-migration-preview','/api/admin/json-migrate-commit','/api/admin/json-migrate','/api/admin/csv-sync','/api/admin/json-migration-status','/api/admin/json-backup'],(req,res)=>res.status(410).json({ok:false,error:'Legacy migration and CSV synchronization are disabled. Use Admin-confirmed pending operation synchronization.'}));
app.get('/api/admin/daily-json-migration-status', async (req, res) => {
  if (!requireAuth(req, res, ['main_admin', 'admin_employee', 'admin_worker'])) return;
  try { return res.json({ ok: true, migration: await getDailyJsonMigrationStatusForAdmin() }); }
  catch (error) { return res.status(503).json({ ok: false, error: 'Daily JSON migration status is unavailable.' }); }
});

app.get('/api/admin/csv-pending-check', async (req,res) => {
  const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if(!auth) return;
  try { return res.json({ok:true,...await getPendingCsvSyncStatus()}); }
  catch(error){ console.error('Pending CSV check failed:',error.message); return res.status(500).json({ok:false,error:'Pending CSV synchronization check failed.',detail:error.message}); }
});

const MIGRATION_ENTITIES = [EMPLOYEE_KEY, ...NON_EMPLOYEE_KEYS];
function migrationRecordId(entity, record) { return entity === EMPLOYEE_KEY ? employeeIdOf(record) : recordId(record); }

const pendingJsonMigrationPlans = new Map();
const JSON_MIGRATION_PLAN_TTL_MS = 30 * 60 * 1000;
let jsonMigrationCommitInProgress = false;
let jsonMigrationCommitWaiter = null;
let jsonMigrationCommitWaiterResolve = null;

function migrationEntityAliases(value) {
  const raw = safeString(value).trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  const aliases = {
    workorders:'fl_workorders', work_orders:'fl_workorders', workorder:'fl_workorders', work_order:'fl_workorders',
    workhistory:'fl_workhistory', work_history:'fl_workhistory', workstatus:'fl_workhistory', work_status:'fl_workhistory',
    attendance:'fl_attendance', employee_attendance:'fl_attendance', permissions:'fl_permissions', permission:'fl_permissions',
    leaves:'fl_leaves', leave:'fl_leaves', sundayot:'fl_sundayot', sunday_ot:'fl_sundayot', overtime:'fl_sundayot',
    employee:'fl_employees', employees:'fl_employees', finance:'fl_finance', financial:'fl_finance', financials:'fl_finance',
    invoices:'fl_invoices', invoice:'fl_invoices', inwards:'fl_invoices', outwards:'fl_invoices', inward:'fl_invoices', outward:'fl_invoices',
    purchase_order:'fl_invoices', purchase_orders:'fl_invoices', purchaseorder:'fl_invoices', purchaseorders:'fl_invoices',
    delivery_challan:'fl_invoices', delivery_challans:'fl_invoices', deliverychallan:'fl_invoices', deliverychallans:'fl_invoices',
    job_status:'fl_workhistory', work_status:'fl_workhistory', powercuts:'fl_powercuts', power_cuts:'fl_powercuts', powercut:'fl_powercuts', power_cut:'fl_powercuts'
  };
  if (raw === EMPLOYEE_KEY || NON_EMPLOYEE_KEYS.includes(raw)) return raw;
  return aliases[raw] || '';
}

function migrationDateFromRecord(record, rowDate) {
  const candidates = [record?.date, record?.entryDate, record?.workDate, record?.attendanceDate,
    record?.requestDate, record?.startDate, record?.otDate, record?.powerDate, record?.paymentDate,
    record?.advanceDate, record?.poDate, record?.salaryPeriod, rowDate, record?.createdAt, record?.created_at];
  for (const candidate of candidates) {
    const value = safeString(candidate).trim();
    if (/^\d{4}-\d{2}-\d{2}(?:[T ].*)?$/.test(value) && !Number.isNaN(Date.parse(value))) return value.slice(0,10);
    if (/^\d{4}-\d{2}$/.test(value)) return `${value}-01`;
    const dmy = value.match(/^(\d{1,2})[/.](\d{1,2})[/.](\d{4})$/);
    if (dmy) {
      const day=Number(dmy[1]), month=Number(dmy[2]), year=Number(dmy[3]);
      if (day>=1 && day<=31 && month>=1 && month<=12) {
        const iso=`${String(year).padStart(4,'0')}-${String(month).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
        if (!Number.isNaN(Date.parse(iso)) && new Date(`${iso}T00:00:00Z`).getUTCDate()===day) return iso;
      }
    }
  }
  return '';
}

function migrationHeaderValue(row, ...names) {
  const entries = Object.entries(row || {});
  for (const wanted of names) {
    const keyWanted = wanted.toLowerCase().replace(/[^a-z0-9]/g, '');
    const found = entries.find(([key]) => key.toLowerCase().replace(/[^a-z0-9]/g, '') === keyWanted);
    if (found && found[1] !== '') return found[1];
  }
  return '';
}

function parseMigrationCsvContent(content, sourcePath) {
  const plain = decryptText(content);
  const rows = parseCsv(plain);
  const records = [];
  const rejected = [];
  const fileEntityGuess = migrationEntityAliases(path.basename(sourcePath, path.extname(sourcePath)));
  for (let index=0; index<rows.length; index++) {
    const row = rows[index];
    let record = rowToRecord(row);
    if (!record) {
      // Support legacy module-specific CSVs where each record is represented
      // directly by columns rather than by the current JSON payload column.
      record = {};
      for (const [key,value] of Object.entries(row || {})) {
        if (!['entity','financial_year','updated_at','month','payload'].includes(key.toLowerCase())) record[key] = value;
      }
    }
    const rowEntity = migrationEntityAliases(migrationHeaderValue(row,'entity','module','record_type')) || fileEntityGuess;
    const entity = rowEntity || migrationEntityAliases(record.entity || record.module || '');
    const rowId = safeString(migrationHeaderValue(row,'id','record_id','employee_id','work_order_id') || record.id || '').trim();
    if (!entity || !(entity === EMPLOYEE_KEY || NON_EMPLOYEE_KEYS.includes(entity))) {
      rejected.push({source:sourcePath,row:index+2,reason:entity ? `Unsupported entity '${entity}'` : 'Entity/module could not be identified'});
      continue;
    }
    if (!rowId) {
      rejected.push({source:sourcePath,row:index+2,entity,reason:'Record identifier is missing'});
      continue;
    }
    record = { ...record, id: rowId };
    const rowDate = migrationHeaderValue(row,'date','record_date','work_date','attendance_date','entry_date');
    const date = migrationDateFromRecord(record,rowDate);
    if (!date) {
      rejected.push({source:sourcePath,row:index+2,entity,id:rowId,reason:'No valid record date; cannot safely determine calendar year'});
      continue;
    }
    // Keep the original payload fields and only fill a missing canonical date
    // from the source row so the existing storage partitioner uses the real date.
    const primaryRecordDate = migrationDateFromRecord({date:record.date,entryDate:record.entryDate,workDate:record.workDate,attendanceDate:record.attendanceDate,requestDate:record.requestDate,startDate:record.startDate,otDate:record.otDate,powerDate:record.powerDate,paymentDate:record.paymentDate,advanceDate:record.advanceDate,poDate:record.poDate,salaryPeriod:record.salaryPeriod},'');
    if (!primaryRecordDate) record.date = date;
    records.push({ entity, id:rowId, date, record:normalizeIsDeleted({ ...record }), source:sourcePath, row:index+2 });
  }
  return { rows:rows.length, records, rejected };
}

async function listAllRemoteMonthlyCsvFiles() {
  if (!githubConfig()) return [];
  const results=[];
  const visited=new Set();
  async function walk(relativePath, depth=0) {
    if (depth>8 || visited.has(relativePath)) return;
    visited.add(relativePath);
    const items=await githubListDirectory(relativePath);
    for (const item of items) {
      const child=`${relativePath}/${item.name}`.replace(/\\/g,'/');
      if (item.type==='dir') await walk(child,depth+1);
      else if (item.type==='file' && /\.csv$/i.test(item.name)) results.push({path:child,source:'github'});
    }
  }
  await walk('monthly');
  return results.sort((a,b)=>a.path.localeCompare(b.path));
}

function listAllLocalMonthlyCsvFiles() {
  const results=[];
  if (!fs.existsSync(MONTHLY_DIR)) return results;
  const root=path.resolve(MONTHLY_DIR);
  const walk=dir=>{
    for (const entry of fs.readdirSync(dir,{withFileTypes:true})) {
      const full=path.join(dir,entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && /\.csv$/i.test(entry.name)) results.push({path:path.relative(CSV_ROOT,full).split(path.sep).join('/'),source:'local',full});
    }
  };
  walk(root);
  return results.sort((a,b)=>a.path.localeCompare(b.path));
}

async function getMigrationSourceContent(source) {
  if (source.source==='local') return fs.readFileSync(source.full,'utf8');
  const remote=await githubReadFile(source.path);
  if (!remote || remote.content==null) throw new Error('Source CSV file is no longer available in GitHub.');
  return remote.content;
}

function chooseCsvJsonRecord(entity, csvRecord, jsonRecord) {
  if (!jsonRecord) return {record:{...csvRecord}, conflict:false, choice:'csv-added'};
  if (sameJsonValue(csvRecord,jsonRecord)) return {record:{...jsonRecord},conflict:false,choice:'identical'};
  const csvTime=recordSyncTimestamp(csvRecord), jsonTime=recordSyncTimestamp(jsonRecord);
  const conflict = csvTime===jsonTime;
  // Newer timestamps win. For equal/missing timestamps preserve JSON because
  // it is the active operational source of truth and must not be rolled back.
  if (jsonTime>=csvTime) return {record:mergeRecordsSafely(entity,jsonRecord,csvRecord),conflict,choice:'json-preserved'};
  return {record:mergeRecordsSafely(entity,csvRecord,jsonRecord),conflict:false,choice:'csv-newer'};
}

function safeMigrationPreviewRecord(entity, record) {
  const out=entity===EMPLOYEE_KEY?employeePublicView(record):{...(record||{})};
  for(const key of Object.keys(out||{})) {
    if(/^(?:image|imageBase64|photo|photoBase64|dataUrl|attachment|fileData)$/i.test(key) && typeof out[key]==='string' && out[key].length>300) out[key]=`[omitted from preview; ${out[key].length} characters; stored value unchanged]`;
  }
  return out;
}

function pruneMigrationPlans() {
  const now=Date.now();
  for (const [id,plan] of pendingJsonMigrationPlans) if (plan.expiresAt<now) pendingJsonMigrationPlans.delete(id);
}

async function buildJsonMigrationPreview() {
  const remoteSources=await listAllRemoteMonthlyCsvFiles();
  const localSources=listAllLocalMonthlyCsvFiles();
  const sources=[...localSources,...remoteSources];
  const sourceReports=[];
  const sourceRecords=[];
  const rejected=[];
  const sourceHashes={};
  for (const source of sources) {
    const key=`${source.source}:${source.path}`;
    try {
      const content=await getMigrationSourceContent(source);
      sourceHashes[key]=crypto.createHash('sha256').update(content).digest('hex');
      const parsed=parseMigrationCsvContent(content,`${source.source}:${source.path}`);
      sourceRecords.push(...parsed.records);
      rejected.push(...parsed.rejected);
      const counts={};
      for (const item of parsed.records) {
        const year=item.date.slice(0,4), month=item.date.slice(0,7), entity=item.entity;
        const k=`${entity}|${year}|${month}`; counts[k]=(counts[k]||0)+1;
      }
      sourceReports.push({source:source.source,path:source.path,parsedRows:parsed.rows,validRecords:parsed.records.length,rejectedRecords:parsed.rejected.length,counts:Object.entries(counts).map(([key,count])=>{const [entity,year,month]=key.split('|');return {entity,year,month,count};})});
    } catch(error) {
      sourceReports.push({source:source.source,path:source.path,parsedRows:0,validRecords:0,rejectedRecords:0,error:error.message});
      rejected.push({source:`${source.source}:${source.path}`,reason:`File could not be decrypted or parsed: ${error.message}`});
    }
  }

  const byEntity=new Map();
  const monthStats=new Map();
  const statsFor=(entity,date)=>{const d=safeString(date);const key=`${entity}|${d.slice(0,4)}|${d.slice(0,7)}`;if(!monthStats.has(key))monthStats.set(key,{found:0,added:0,updated:0,preserved:0,skipped:0,duplicates:0,rejected:0});return monthStats.get(key);};
  for (const entity of MIGRATION_ENTITIES) {
    const existing=entity===EMPLOYEE_KEY ? (await getEmployeesFromStore(true)) : loadEntityAll(entity);
    const existingById=new Map(existing.map(record=>[migrationRecordId(entity,record),{...record}]));
    const csvById=new Map();
    let duplicateCsvRecords=0;
    for (const item of sourceRecords.filter(x=>x.entity===entity)) {
      const itemId=migrationRecordId(entity,item.record) || item.id;
      const old=csvById.get(itemId);
      statsFor(entity,item.date).found++;
      if (!old) csvById.set(itemId,{...item.record,id:itemId,__migrationDate:item.date,__migrationSources:[item.source]});
      else {
        duplicateCsvRecords++;
        statsFor(entity,item.date).duplicates++;
        const chosen=chooseCsvJsonRecord(entity,old,item.record);
        csvById.set(itemId,{...chosen.record,id:itemId,__migrationDate:chosen.record.__migrationDate||item.date,__migrationSources:[...(old.__migrationSources||[]),item.source]});
      }
    }
    const merged=new Map(existingById);
    let added=0,updated=0,preserved=0,conflictCount=0;
    const conflicts=[];
    for (const [id,csvRecordRaw] of csvById) {
      const csvRecord={...csvRecordRaw};
      const migrationDate=safeString(csvRecord.__migrationDate); delete csvRecord.__migrationDate; delete csvRecord.__migrationSources;
      if (!migrationDateFromRecord(csvRecord,'')) csvRecord.date=migrationDate;
      const jsonRecord=existingById.get(id);
      if (!jsonRecord) { merged.set(id,csvRecord); added++; statsFor(entity,migrationDate).added++; continue; }
      const chosen=chooseCsvJsonRecord(entity,csvRecord,jsonRecord);
      if (chosen.conflict) {
        conflictCount++;
        if (conflicts.length<200) conflicts.push({entity,id,date:migrationDate,reason:'CSV and JSON records differ but have equal or missing update timestamps; existing JSON will be preserved unless review indicates otherwise.'});
      }
      if (chosen.choice==='csv-newer') { updated++; statsFor(entity,migrationDate).updated++; }
      else { preserved++; statsFor(entity,migrationDate).preserved++; statsFor(entity,migrationDate).skipped++; }
      merged.set(id,chosen.record);
    }
    const byYear={};
    for (const record of merged.values()) {
      const date=migrationDateFromRecord(record,'');
      const year=date ? date.slice(0,4) : 'unknown';
      byYear[year]=(byYear[year]||0)+1;
    }
    byEntity.set(entity,{records:[...merged.values()],existingCount:existing.length,csvUniqueRecords:csvById.size,added,updated,preserved,duplicateCsvRecords,conflictCount,conflicts,byYear});
  }

  const monthYearCounts={};
  for (const item of sourceRecords) {
    const key=`${item.entity}|${item.date.slice(0,4)}|${item.date.slice(0,7)}`;
    monthYearCounts[key]=(monthYearCounts[key]||0)+1;
  }
  for(const rejectedRow of rejected){
    const source=safeString(rejectedRow.source);
    const fileMonth=source.match(/(?:^|\/)(\d{4})[-_]?((?:0[1-9])|(?:1[0-2]))(?:\.csv)?(?:$|:)/i);
    if(fileMonth){const entity=rejectedRow.entity||'unknown';const year=fileMonth[1],month=`${year}-${fileMonth[2]}`;const key=`${entity}|${year}|${month}`;monthYearCounts[key]=monthYearCounts[key]||0;statsFor(entity,`${month}-01`).rejected++;}
  }
  const monthSummary=Object.entries(monthYearCounts).map(([key,count])=>{const [entity,year,month]=key.split('|');const stats=monthStats.get(key)||{added:0,updated:0,preserved:0,skipped:0,duplicates:0,rejected:0};return {entity,year,month,count,found:count,added:stats.added,updated:stats.updated,preserved:stats.preserved,skipped:stats.skipped,duplicates:stats.duplicates,rejected:stats.rejected};}).sort((a,b)=>a.year.localeCompare(b.year)||a.month.localeCompare(b.month)||a.entity.localeCompare(b.entity));
  const entitySummary=[...byEntity.entries()].map(([entity,item])=>({entity,sourceCsvUniqueRecords:item.csvUniqueRecords,jsonRecordsBefore:item.existingCount,proposedJsonRecords:item.records.length,added:item.added,updated:item.updated,preserved:item.preserved,skipped:item.preserved,duplicates:item.duplicateCsvRecords,conflicts:item.conflictCount,byYear:item.byYear}));
  const previewRecords=[];
  for (const [entity,item] of byEntity) {
    for (const record of item.records) {
      if (previewRecords.length>=100) break;
      const date=migrationDateFromRecord(record,'');
      const id=migrationRecordId(entity,record);
      previewRecords.push({entity,id,date,year:date?date.slice(0,4):'unknown',status:item.records.length? (item.conflicts.some(c=>c.id===id)?'conflict-review':'merged'): 'merged',record});
    }
    if (previewRecords.length>=100) break;
  }
  const planId=crypto.randomBytes(24).toString('hex');
  const plan={id:planId,createdAt:new Date().toISOString(),expiresAt:Date.now()+JSON_MIGRATION_PLAN_TTL_MS,sourceHashes,sourceReports,rejected,sourceRecords,byEntity,monthSummary,entitySummary,previewRecords,remoteConfigured:!!githubConfig()};
  pruneMigrationPlans(); pendingJsonMigrationPlans.set(planId,plan);
  return {plan,publicPreview:{planId,createdAt:plan.createdAt,expiresInMinutes:30,remoteConfigured:plan.remoteConfigured,sourceFiles:sourceReports,monthSummary,entitySummary,rejectedCount:rejected.length,rejectedPreview:rejected.slice(0,100),conflicts:entitySummary.reduce((n,x)=>n+x.conflicts,0),conflictPreview:[...byEntity.values()].flatMap(x=>x.conflicts).slice(0,100),previewRecords:previewRecords.map(x=>({entity:x.entity,id:x.id,date:x.date,year:x.year,status:x.status,record:safeMigrationPreviewRecord(x.entity,x.record)})),sourceRecordCount:sourceRecords.length,entityCount:byEntity.size}};
}

// Expose only non-sensitive Boolean feature flags needed by the UI.
app.get('/api/public-features', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  return res.json({ ok: true, features: { jsonBackup: false, dailyJsonYearwiseMigration: false } });
});

app.get('/api/admin/json-migration-status', (req, res) => {
  const auth = requireAuth(req, res, ['main_admin','admin_employee','admin_worker']);
  if (!auth) return;
  if (!ENABLE_LEGACY_CSV_JSON_RECOVERY) return res.status(403).json({ok:false,error:'CSV-to-JSON migration is disabled.'});
  try {
    const entities = MIGRATION_ENTITIES.map(entity => readJsonMigrationMarker(entity) || { entity, complete: false, status: 'pending' });
    return res.json({ok:true,storage:'encrypted-partitioned-json',employeeStorage:'unchanged-employees.json-flow',csvMigrationEnabled:ENABLE_LEGACY_CSV_JSON_RECOVERY,complete:entities.every(item=>item.complete===true),entities});
  } catch (error) {
    console.error('JSON migration status failed:', error.message);
    return res.status(500).json({ ok: false, error: 'JSON migration status could not be read.' });
  }
});

app.post('/api/admin/json-migration-preview', async (req,res) => {
  const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if(!auth) return;
  if(!ENABLE_LEGACY_CSV_JSON_RECOVERY) return res.status(403).json({ok:false,error:'CSV-to-JSON recovery is disabled. Set ENABLE_LEGACY_CSV_JSON_RECOVERY=true temporarily to preview and migrate.'});
  try {
    const {publicPreview}=await buildJsonMigrationPreview();
    return res.json({ok:true,preview:publicPreview});
  } catch(error) {
    console.error('CSV-to-JSON preview failed:',error.message,error.stack||'');
    return res.status(500).json({ok:false,error:'CSV-to-JSON preview failed before any data was changed.',detail:error.message});
  }
});

app.post('/api/admin/json-migrate-commit', async (req,res) => {
  const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if(!auth) return;
  if(!ENABLE_LEGACY_CSV_JSON_RECOVERY) return res.status(403).json({ok:false,error:'CSV-to-JSON recovery is disabled. Set ENABLE_LEGACY_CSV_JSON_RECOVERY=true temporarily to run it.'});
  if(jsonMigrationCommitInProgress) return res.status(409).json({ok:false,error:'A CSV-to-JSON migration is already running.'});
  pruneMigrationPlans();
  const planId=safeString(req.body?.planId).trim();
  const plan=pendingJsonMigrationPlans.get(planId);
  if(!plan) return res.status(410).json({ok:false,error:'Migration preview expired or was not found. Create a new preview.'});
  if(!req.body?.confirm) return res.status(400).json({ok:false,error:'Explicit confirmation is required before committing migrated JSON.'});
  if(plan.rejected.length) return res.status(409).json({ok:false,error:'Some source rows/files were rejected. Review the preview and correct the source data before committing.',rejectedCount:plan.rejected.length,rejectedPreview:plan.rejected.slice(0,100)});
  const conflicts=[...plan.byEntity.values()].reduce((n,x)=>n+x.conflictCount,0);
  if(conflicts && req.body?.confirmConflicts!==true) return res.status(409).json({ok:false,error:'Conflicts with equal or missing timestamps require explicit acknowledgement. Existing JSON values will be preserved for those conflicts.',conflicts});
  if(!githubConfig()) return res.status(503).json({ok:false,error:'GitHub backup is not configured. Configure GITHUB_TOKEN and GITHUB_REPO before committing the migration.'});
  jsonMigrationCommitInProgress=true;
  jsonMigrationCommitWaiter=new Promise(resolve=>{jsonMigrationCommitWaiterResolve=resolve;});
  const startedAt=Date.now(), results=[], remoteFiles=[];
  try {
    // Drain writes that were already accepted before migration began. New writes wait on the migration lock.
    await durableCsvWriteQueue;
    await employeeWriteQueue;
    // Ensure the source has not changed since preview; preserve all original CSVs.
    const sources=[...listAllLocalMonthlyCsvFiles(),...await listAllRemoteMonthlyCsvFiles()];
    const currentSourceKeys=new Set(sources.map(source=>`${source.source}:${source.path}`));
    const plannedSourceKeys=new Set(Object.keys(plan.sourceHashes));
    if(currentSourceKeys.size!==plannedSourceKeys.size || [...currentSourceKeys].some(key=>!plannedSourceKeys.has(key))) return res.status(409).json({ok:false,error:'The monthly CSV file inventory changed after preview. Create a new preview before committing.'});
    for(const source of sources){
      const key=`${source.source}:${source.path}`;
      if(!(key in plan.sourceHashes)) continue;
      const content=await getMigrationSourceContent(source);
      const currentHash=crypto.createHash('sha256').update(content).digest('hex');
      if(currentHash!==plan.sourceHashes[key]) return res.status(409).json({ok:false,error:`Source changed after preview: ${key}. Create a new preview before committing.`});
    }
    if(plan.sourceReports.length===0) return res.status(409).json({ok:false,error:'No monthly CSV files were found. Nothing can be migrated; no JSON or GitHub files were changed.'});
    for(const [entity,item] of plan.byEntity){
      let markerPathForRun=''; let previousMarkerContent=null; let markerVerifiedForRun=false;
      try {
        if(entity===EMPLOYEE_KEY){
          const latestEmployees=(await getEmployeesFromStore(true)).map(normalizeEmployee).filter(Boolean);
          const latestEmployeeById=new Map(latestEmployees.map(employee=>[employeeIdOf(employee),employee]));
          for(const plannedRecord of item.records){
            const planned=normalizeEmployee(plannedRecord); if(!planned) continue;
            const id=employeeIdOf(planned); if(!id) continue;
            const latest=latestEmployeeById.get(id);
            latestEmployeeById.set(id,latest?chooseCsvJsonRecord(entity,planned,latest).record:planned);
          }
          const employeeRecords=[...latestEmployeeById.values()].map(normalizeEmployee).filter(Boolean);
          await writeEmployeeJsonToGitHub(employeeRecords);
          const employeeRemote=await githubReadFile(employeeJsonRelativePath());
          if(!employeeRemote?.content) throw new Error('Employee JSON GitHub read-back verification failed.');
          const employeeVerified=decryptJsonText(employeeRemote.content).map(normalizeEmployee).filter(Boolean).sort(compareEmployeeId);
          const expectedEmployees=employeeRecords.slice().sort(compareEmployeeId);
          if(JSON.stringify(employeeVerified)!==JSON.stringify(expectedEmployees)) throw new Error('Employee JSON GitHub record verification failed.');
          const employeeMarkerPathLocal=jsonMigrationMarkerPath(entity);
          previousMarkerContent=fs.existsSync(employeeMarkerPathLocal)?fs.readFileSync(employeeMarkerPathLocal,'utf8'):null;
          const employeeMarker=writeJsonMigrationMarker(entity,{sourceCsvMonths:new Set(plan.sourceRecords.filter(x=>x.entity===entity).map(x=>x.date.slice(0,7))).size,sourceCsvUniqueRecords:item.csvUniqueRecords,jsonRecordsBefore:item.existingCount,jsonRecordsAfter:employeeRecords.length,processedRecords:item.csvUniqueRecords,migratedRecords:item.added,updatedRecords:item.updated,preservedRecords:item.preserved,skippedRecords:item.preserved,duplicateRecords:item.duplicateCsvRecords,conflictRecords:item.conflictCount,rejectedRecords:0,githubVerifiedFiles:1,githubVerified:true,storage:'employees.json'});
          markerPathForRun=employeeMarkerPathLocal;
          const employeeMarkerPath=path.relative(CSV_ROOT,employeeMarkerPathLocal).split(path.sep).join('/');
          const employeeMarkerContent=fs.readFileSync(employeeMarkerPathLocal,'utf8');
          if(!await githubWriteFile(employeeMarkerPath,employeeMarkerContent,'Verify SOV employee JSON migration')) throw new Error('Employee migration marker GitHub write failed.');
          await verifyGitHubJsonDocument(employeeMarkerPath, employeeMarkerContent, 'Employee migration marker GitHub');
          markerVerifiedForRun=true;
          remoteFiles.push(employeeJsonRelativePath(),employeeMarkerPath);
          results.push({entity,ok:true,...employeeMarker});
          continue;
        }
        const current=loadEntityAll(entity);
        const latestById=new Map(current.map(record=>[recordId(record),{...record}]));
        for(const plannedRecord of item.records){
          const id=recordId(plannedRecord); if(!id) continue;
          const latest=latestById.get(id);
          latestById.set(id,latest?chooseCsvJsonRecord(entity,plannedRecord,latest).record:{...plannedRecord});
        }
        entityAllJsonCache.delete(entity);
        writeEntityAllToJson(entity,[...latestById.values()],true);
        const files=listJsonPartitionFiles(entity);
        let verifiedCount=0;
        for(const file of files){
          const relative=path.relative(CSV_ROOT,file).split(path.sep).join('/');
          const content=fs.readFileSync(file,'utf8');
          const saved=await githubWriteFile(relative,content,`Migrate SOV ${entity} JSON records`);
          if(!saved) throw new Error(`GitHub write failed for ${relative}`);
          const remote=await githubReadFile(relative);
          if(!remote?.content || !sameStoredContent(remote.content,content)) throw new Error(`GitHub read-back verification failed for ${relative}`);
          remoteFiles.push(relative); verifiedCount++;
        }
        const markerPathLocal=jsonMigrationMarkerPath(entity);
        previousMarkerContent=fs.existsSync(markerPathLocal)?fs.readFileSync(markerPathLocal,'utf8'):null;
        const marker=writeJsonMigrationMarker(entity,{sourceCsvMonths:new Set(plan.sourceRecords.filter(x=>x.entity===entity).map(x=>x.date.slice(0,7))).size,sourceCsvUniqueRecords:item.csvUniqueRecords,jsonRecordsBefore:item.existingCount,jsonRecordsAfter:item.records.length,processedRecords:item.csvUniqueRecords,migratedRecords:item.added,updatedRecords:item.updated,preservedRecords:item.preserved,skippedRecords:item.preserved,duplicateRecords:item.duplicateCsvRecords,conflictRecords:item.conflictCount,rejectedRecords:0,githubVerifiedFiles:verifiedCount,githubVerified:true});
        markerPathForRun=markerPathLocal;
        const markerRelative=path.relative(CSV_ROOT,markerPathLocal).split(path.sep).join('/');
        const markerContent=fs.readFileSync(markerPathLocal,'utf8');
        if(!await githubWriteFile(markerRelative,markerContent,`Verify SOV ${entity} JSON migration`)) throw new Error(`GitHub marker write failed for ${entity}`);
        await verifyGitHubJsonDocument(markerRelative, markerContent, `GitHub migration marker for ${entity}`);
        markerVerifiedForRun=true;
        remoteFiles.push(markerRelative);
        results.push({entity,ok:true,...marker});
      } catch(error) {
        if(markerPathForRun && !markerVerifiedForRun) {
          try { if(previousMarkerContent!=null) fs.writeFileSync(markerPathForRun,previousMarkerContent,'utf8'); else fs.rmSync(markerPathForRun,{force:true}); } catch(_) {}
          jsonMigrationStatus.delete(entity);
        }
        console.error(`CSV-to-JSON commit failed for ${entity}:`,error.message);
        results.push({entity,ok:false,error:error.message});
      }
    }
    const failed=results.filter(x=>!x.ok);
    if(!failed.length) pendingJsonMigrationPlans.delete(planId);
    const failureDetails=failed.map(item=>`${item.entity}: ${safeString(item.error||'Unknown entity migration error')}`);
    return res.status(failed.length?500:200).json({
      ok:failed.length===0,
      error:failed.length ? 'Migration commit failed for one or more modules.' : undefined,
      detail:failureDetails.length ? failureDetails.join(' | ').slice(0,4000) : undefined,
      durationMs:Date.now()-startedAt,
      sourceFiles:plan.sourceReports.length,
      sourceRecords:plan.sourceRecords.length,
      rejectedRecords:plan.rejected.length,
      conflictsAcknowledged:conflicts>0,
      githubVerified:failed.length===0,
      githubVerifiedFiles:remoteFiles.length,
      failedEntities:failed.length,
      results,
      sourceFilesReport:plan.sourceReports,
      monthSummary:plan.monthSummary,
      entitySummary:plan.entitySummary
    });
  } catch(error) {
    console.error('CSV-to-JSON commit failed:',error.message,error.stack||'');
    return res.status(500).json({ok:false,error:'Migration did not complete and verify in GitHub.',detail:error.message,githubVerified:false,verifiedFilesBeforeFailure:remoteFiles});
  } finally {
    jsonMigrationCommitInProgress=false;
    if (typeof jsonMigrationCommitWaiterResolve==='function') jsonMigrationCommitWaiterResolve();
    jsonMigrationCommitWaiter=null; jsonMigrationCommitWaiterResolve=null;
  }
});

// Compatibility guard for older frontends that still call the previous direct-migration endpoint.
// It deliberately does not commit without a preview and explicit confirmation.
app.post('/api/admin/json-migrate', (req,res) => {
  const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if(!auth) return;
  if(!ENABLE_LEGACY_CSV_JSON_RECOVERY) return res.status(403).json({ok:false,error:'CSV-to-JSON recovery is disabled. Set ENABLE_LEGACY_CSV_JSON_RECOVERY=true temporarily to preview and migrate.'});
  return res.status(409).json({ok:false,error:'Migration now requires a preview and explicit confirmation. Reload the application and use Recover CSV to JSON to review the source files before committing.'});
});

// Manual backup is persisted in the configured GitHub repository under the
// repository-root backup/ folder. Local temp files are staging only, never the
// success criterion. The ZIP preserves the full relative data/csv tree.
const JSON_BACKUP_ROOT = path.join(CSV_ROOT, 'backups', 'json');
let jsonBackupInProgress = false;
function sha256File(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function countJsonRecords(file) {
  if (/\.enc$/i.test(file)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (Array.isArray(parsed)) return parsed.length;
    for (const key of ['records','rows','items','employees','attendance','workOrders','workorders']) if (Array.isArray(parsed?.[key])) return parsed[key].length;
    return parsed && typeof parsed === 'object' ? Object.keys(parsed).length : 1;
  } catch (_) { return null; }
}
function collectJsonBackupFiles() {
  const found=[];
  const backupRoot=path.resolve(JSON_BACKUP_ROOT)+path.sep;
  const walk=dir=>{
    if(!fs.existsSync(dir)) return;
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      const full=path.join(dir,entry.name); const resolved=path.resolve(full);
      if(resolved===path.resolve(JSON_BACKUP_ROOT) || resolved.startsWith(backupRoot)) continue;
      if(entry.isDirectory()) walk(full);
      else if(entry.isFile() && !/\.tmp(?:-|$)/i.test(entry.name) && (/\.json$/i.test(entry.name)||/\.json\.enc$/i.test(entry.name))) found.push(full);
    }
  };
  walk(CSV_ROOT);
  return found.sort();
}
function createZipFromDirectory(sourceDir, zipPath) {
  return new Promise((resolve,reject)=>{
    const output=fs.createWriteStream(zipPath,{flags:'wx'});
    const archive=archiver('zip',{zlib:{level:6}});
    let settled=false;
    const fail=error=>{ if(!settled){settled=true; try{output.destroy();}catch(_){} reject(error);} };
    output.once('close',()=>{if(!settled){settled=true;resolve(archive.pointer());}});
    output.once('error',fail); archive.once('error',fail);
    archive.pipe(output); archive.directory(sourceDir,false);
    Promise.resolve(archive.finalize()).catch(fail);
  });
}
function verifyZipArchive(zipPath) {
  const stat=fs.statSync(zipPath);
  if(stat.size<22) throw new Error('Generated ZIP is too small to be a valid archive.');
  const fd=fs.openSync(zipPath,'r');
  try {
    const tailLength=Math.min(stat.size,65557);
    const tail=Buffer.alloc(tailLength);
    fs.readSync(fd,tail,0,tailLength,stat.size-tailLength);
    let eocd=-1;
    for(let i=tail.length-22;i>=0;i--){if(tail.readUInt32LE(i)===0x06054b50){eocd=i;break;}}
    if(eocd<0) throw new Error('Generated ZIP is missing its end-of-central-directory record.');
    const entries=tail.readUInt16LE(eocd+10);
    const centralSize=tail.readUInt32LE(eocd+12);
    const centralOffset=tail.readUInt32LE(eocd+16);
    if(entries<1 || centralOffset+centralSize>stat.size) throw new Error('Generated ZIP central directory failed validation.');
    return {entries,size:stat.size};
  } finally { fs.closeSync(fd); }
}
app.get('/api/admin/json-backup/status', async (req,res) => {
  if(!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  if(!ENABLE_JSON_BACKUP) return res.status(403).json({ok:false,error:'JSON backup is disabled.'});
  try {
    const config=githubConfig();
    if(!config) return res.json({ok:true,available:false,repository:null,backupFolder:'backup',syncStatus:'not-configured'});
    const content=await githubReadRepositoryText('backup/manifest.json');
    if(!content) return res.json({ok:true,available:false,repository:config.repo,backupFolder:'backup',syncStatus:'no-verified-backup'});
    const manifest=JSON.parse(content);
    if(manifest.verificationStatus!=='verified' || !manifest.archivePath || !manifest.archiveSha256) return res.json({ok:true,available:false,repository:config.repo,backupFolder:'backup',syncStatus:'manifest-not-verified'});
    return res.json({ok:true,available:true,repository:config.repo,backupFolder:'backup',createdAt:manifest.createdAt,archivePath:manifest.archivePath,archiveSize:manifest.archiveSize,archiveSha256:manifest.archiveSha256,yearlyJsonBackups:Array.isArray(manifest.yearlyJsonBackups)?manifest.yearlyJsonBackups:[],commitSha:manifest.commitSha||null,syncStatus:'verified-on-github'});
  } catch(error) { console.error('JSON backup status failed:',error.message); return res.status(502).json({ok:false,error:'Could not verify the latest GitHub JSON backup.',detail:error.message}); }
});
async function buildYearlyJsonBackupArtifacts(createdAt, businessDate, stageDir) {
  const recordsByYear = new Map();
  const ensureYear = year => {
    if (!recordsByYear.has(year)) {
      const entities = {};
      for (const entity of NON_EMPLOYEE_KEYS) entities[entity] = [];
      entities[EMPLOYEE_KEY] = [];
      recordsByYear.set(year, { version:1, type:'SOV_YEAR_WISE_JSON_BACKUP', year, createdAt, entities });
    }
    return recordsByYear.get(year);
  };
  for (const entity of NON_EMPLOYEE_KEYS) {
    const records = loadEntityAllFromJson(entity);
    for (const record of records) {
      const date = recordDate(entity, record);
      const year = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date.slice(0,4) : businessDate.slice(0,4);
      ensureYear(year).entities[entity].push({ ...record });
    }
  }
  // Employee records are stored separately in the existing application. Include
  // them in the year package using joining/creation date where available; records
  // without a usable date are retained in the business-current-year package.
  try {
    const employees = await getEmployeesFromStore(true);
    for (const employee of employees) {
      const date = safeString(employee.joiningDate || employee.dateOfJoining || employee.createdAt || employee.created_at || '').slice(0,10);
      const year = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date.slice(0,4) : businessDate.slice(0,4);
      ensureYear(year).entities[EMPLOYEE_KEY].push({ ...employee });
    }
  } catch (error) {
    throw new Error(`Employee records could not be included in the year-wise backup: ${error.message}`);
  }
  if (!recordsByYear.size) ensureYear(businessDate.slice(0,4));

  const artifacts = [];
  for (const [year, payload] of [...recordsByYear.entries()].sort(([a],[b]) => a.localeCompare(b))) {
    for (const entity of Object.keys(payload.entities)) {
      payload.entities[entity].sort((a,b) => recordId(a).localeCompare(recordId(b), undefined, {numeric:true}));
    }
    let version = 1;
    let filename = '';
    let remotePath = '';
    while (version < 10000) {
      filename = `sov_${year}_backup_${businessDate}_v${version}.json`;
      remotePath = `backup/yearly-json/${filename}`;
      const existing = await githubReadRepositoryText(remotePath);
      if (existing == null) break;
      version++;
    }
    if (version >= 10000) throw new Error(`Could not allocate a unique backup version for year ${year}.`);
    const encryptedPayload = encryptJsonText(payload);
    const artifact = {
      format:'SOV_ENCRYPTED_YEAR_JSON_BACKUP',
      version:1,
      year,
      createdAt,
      businessDate,
      encryption:'application CSV_ENCRYPTION_KEY envelope; decrypt with decryptText()',
      encryptedPayload
    };
    const localDir = path.join(stageDir, 'yearly-json');
    fs.mkdirSync(localDir, {recursive:true});
    const localPath = path.join(localDir, filename);
    fs.writeFileSync(localPath, JSON.stringify(artifact, null, 2), 'utf8');
    artifacts.push({year, version, filename, path:remotePath, localPath, recordCount:Object.values(payload.entities).reduce((sum,list)=>sum+list.length,0), sha256:sha256File(localPath), size:fs.statSync(localPath).size});
  }
  return artifacts;
}

app.post('/api/admin/json-backup', async (req,res) => {
  if(!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  if(!ENABLE_JSON_BACKUP) return res.status(403).json({ok:false,error:'JSON backup is disabled.'});
  if(jsonBackupInProgress) return res.status(409).json({ok:false,error:'A JSON backup is already running.'});
  const config=githubConfig();
  if(!config) return res.status(503).json({ok:false,error:'Persistent GitHub backup is not configured. Set GITHUB_TOKEN and GITHUB_REPO.'});
  jsonBackupInProgress=true;
  const startedAt=Date.now();
  const createdAt=new Date().toISOString();
  const stamp=createdAt.replace(/[:.]/g,'-');
  const dateLabel=createdAt.slice(0,16).replace('T','_').replace(/:/g,'-');
  const filename=`SOV_Engineering_JSON_Backup_${dateLabel}.zip`;
  const versionDir=`backup/versions/${stamp}`;
  const archivePath=`${versionDir}/${filename}`;
  const stageDir=fs.mkdtempSync(path.join(require('os').tmpdir(),'sov-json-backup-stage-'));
  const dataRoot=path.join(stageDir,'data','csv');
  const zipPath=path.join(require('os').tmpdir(),`sov-json-backup-${process.pid}-${Date.now()}.zip`);
  const failedFiles=[]; let copied=0;
  try {
    // A manual backup is an explicit, non-login operation: reconcile GitHub
    // operational partitions first, then stage verified pending/recovery copies.
    await restoreOperationalJsonFromGitHubIfNeeded();
    const pendingForBackup = await loadPersistentPendingState();
    const csvPendingForBackup = await loadPersistentCsvSyncPendingState();
    writeDailyJsonIfChanged(PREVIOUS_PENDING_JSON_LOCAL, pendingForBackup);
    writeDailyJsonIfChanged(CSV_SYNC_PENDING_JSON_LOCAL, csvPendingForBackup);
    fs.mkdirSync(dataRoot,{recursive:true});
    const files=collectJsonBackupFiles();
    if(!files.length) throw new Error('No JSON data files were found to back up.');
    const fileManifest=[];
    for(const source of files){
      const rel=path.relative(CSV_ROOT,source).split(path.sep).join('/');
      const dest=path.join(dataRoot,...rel.split('/'));
      try {
        fs.mkdirSync(path.dirname(dest),{recursive:true});
        fs.copyFileSync(source,dest,fs.constants.COPYFILE_EXCL);
        const sourceStat=fs.statSync(source), targetStat=fs.statSync(dest);
        const sourceHash=sha256File(source), targetHash=sha256File(dest);
        if(sourceStat.size!==targetStat.size || sourceHash!==targetHash) throw new Error('Staged file verification mismatch');
        fileManifest.push({path:`data/csv/${rel}`,sourcePath:rel,size:sourceStat.size,sha256:sourceHash,recordCount:countJsonRecords(source)}); copied++;
      } catch(error) { failedFiles.push({file:rel,error:error.message}); }
    }
    if(failedFiles.length) throw new Error(`Could not stage ${failedFiles.length} JSON file(s); no GitHub backup was committed.`);
    const yearlyArtifacts = await buildYearlyJsonBackupArtifacts(createdAt, appTodayStr(), stageDir);
    for (const artifact of yearlyArtifacts) {
      const rel = `yearly-json/${artifact.filename}`;
      const dest = path.join(stageDir, ...rel.split('/'));
      fs.mkdirSync(path.dirname(dest), {recursive:true});
      if (dest !== artifact.localPath) fs.copyFileSync(artifact.localPath, dest);
      const sha = sha256File(dest);
      if (sha !== artifact.sha256) throw new Error(`Year-wise backup staging verification failed for ${artifact.filename}.`);
      fileManifest.push({path:rel,sourcePath:artifact.path,size:fs.statSync(dest).size,sha256:sha,recordCount:artifact.recordCount,encrypted:true,year:artifact.year,version:artifact.version});
    }
    const internalManifest={version:2,createdAt,repository:config.repo,backupFolder:'backup',sourceRoot:'data/csv',fileCount:fileManifest.length,files:fileManifest,yearlyJsonBackups:yearlyArtifacts.map(({localPath,...item})=>item),sourceFilesVerified:true,verificationStatus:'source-copy-verified'};
    fs.writeFileSync(path.join(stageDir,'manifest.json'),JSON.stringify(internalManifest,null,2),'utf8');
    fs.writeFileSync(path.join(stageDir,'README.txt'),`SOV Engineering JSON backup\nCreated: ${createdAt}\nRepository: ${config.repo}\nBackup folder: backup/\nArchive includes the data/csv/ directory tree and manifest.json.\nOriginal monthly CSV files are not modified by this backup operation.\n`, 'utf8');
    await createZipFromDirectory(stageDir,zipPath);
    const zipValidation=verifyZipArchive(zipPath);
    const archiveStat=fs.statSync(zipPath);
    const configuredMaxMb=Number(process.env.GITHUB_BACKUP_MAX_MB||45);
    const maxMb=Number.isFinite(configuredMaxMb)?Math.max(5,configuredMaxMb):45;
    if(archiveStat.size>maxMb*1024*1024) throw new Error(`Backup archive is ${(archiveStat.size/1024/1024).toFixed(1)} MB, above the configured GitHub Contents API safety limit of ${maxMb} MB. No archive was committed. Configure a suitable durable object-storage provider for larger backups or raise GITHUB_BACKUP_MAX_MB after assessing Render memory limits.`);
    const archiveBuffer=fs.readFileSync(zipPath);
    const archiveSha=crypto.createHash('sha256').update(archiveBuffer).digest('hex');
    const versionManifest={...internalManifest,archivePath,archiveSize:archiveStat.size,archiveSha256:archiveSha,archiveEntries:zipValidation.entries,githubVerificationStatus:'pending'};
    await githubWriteRepositoryText(`${versionDir}/manifest.json`,JSON.stringify(versionManifest,null,2),`Store SOV JSON backup manifest ${stamp}`);
    await githubWriteRepositoryText(`${versionDir}/README.txt`,`SOV Engineering JSON backup\nCreated: ${createdAt}\nArchive: ${filename}\nSHA-256: ${archiveSha}\nSource files: ${fileManifest.length}\n`, `Store SOV JSON backup readme ${stamp}`);
    const remoteArchive=await githubWriteRepositoryBinary(archivePath,archiveBuffer,`Store SOV Engineering JSON backup ${stamp}`);
    // Publish each per-year encrypted JSON artifact with the required stable
    // naming convention. githubWriteRepositoryText verifies each committed file.
    const verifiedYearlyBackups = [];
    for (const artifact of yearlyArtifacts) {
      const content = fs.readFileSync(artifact.localPath, 'utf8');
      const saved = await githubCreateRepositoryTextImmutable(artifact.path, content, `Store SOV year-wise JSON backup ${artifact.filename}`);
      if (!saved?.verified) throw new Error(`GitHub year-wise backup verification failed for ${artifact.filename}.`);
      const remoteText = await githubReadRepositoryText(artifact.path);
      if (remoteText == null || crypto.createHash('sha256').update(Buffer.from(remoteText,'utf8')).digest('hex') !== crypto.createHash('sha256').update(Buffer.from(content,'utf8')).digest('hex')) throw new Error(`GitHub year-wise backup read-back hash failed for ${artifact.filename}.`);
      verifiedYearlyBackups.push({year:artifact.year,version:artifact.version,filename:artifact.filename,path:artifact.path,recordCount:artifact.recordCount,size:Buffer.byteLength(content,'utf8'),sha256:crypto.createHash('sha256').update(Buffer.from(content,'utf8')).digest('hex'),verificationStatus:'verified'});
    }
    // Latest pointer is committed only after archive and all yearly artifacts
    // have been committed and read back successfully.
    const rootManifest={version:2,createdAt,repository:config.repo,branch:config.branch,backupFolder:'backup',archivePath,archiveFile:filename,archiveSize:archiveStat.size,archiveSha256:archiveSha,archiveEntries:zipValidation.entries,fileCount:fileManifest.length,files:fileManifest,yearlyJsonBackups:verifiedYearlyBackups,verificationStatus:'verified',githubVerificationStatus:'verified-by-readback-sha256',githubArchiveReadbackSha256:remoteArchive.sha256,githubArchiveReadbackSize:remoteArchive.size,durationMs:Date.now()-startedAt};
    await githubWriteRepositoryText('backup/README.txt',`SOV Engineering persistent JSON backups\nRepository: ${config.repo}\nLatest verified backup: ${createdAt}\nLatest archive: ${archivePath}\nThe archive contains all staged JSON and encrypted JSON files under data/csv/, preserving relative paths.\nSee manifest.json for file hashes, sizes, record counts where available, and verification status.\n`, 'Update SOV JSON backup README');
    await githubWriteRepositoryText('backup/manifest.json',JSON.stringify(rootManifest,null,2),'Publish verified SOV JSON backup manifest');
    // Verify the authoritative latest manifest after its GitHub commit.
    const remoteManifestText=await githubReadRepositoryText('backup/manifest.json');
    const remoteManifest=JSON.parse(remoteManifestText||'null');
    if(!remoteManifest || remoteManifest.verificationStatus!=='verified' || remoteManifest.archiveSha256!==archiveSha || remoteManifest.archivePath!==archivePath) throw new Error('GitHub latest backup manifest read-back verification failed. The archive may exist, but the backup is not marked successful.');
    return res.json({ok:true,backupType:'github-repository',persistent:true,repository:config.repo,branch:config.branch,backupFolder:'backup/',backupDirectory:versionDir,archivePath,archiveFile:filename,createdAt,syncStatus:'verified-on-github',verificationStatus:'verified',archiveSize:archiveStat.size,archiveSha256:archiveSha,archiveEntries:zipValidation.entries,copiedFiles:copied,fileCount:fileManifest.length,yearlyJsonBackups:verifiedYearlyBackups,failedFiles:[],manifestPath:'backup/manifest.json',durationMs:Date.now()-startedAt,downloadAvailable:true});
  } catch(error) {
    console.error('Manual GitHub JSON backup failed:',error.message,error.stack||'');
    return res.status(500).json({ok:false,error:'GitHub JSON backup failed. Success was not reported.',detail:error.message,repository:config.repo,backupFolder:'backup/',copiedFiles:copied,failedFiles,partialArchivePath:archivePath});
  } finally {
    jsonBackupInProgress=false;
    try{fs.rmSync(stageDir,{recursive:true,force:true});}catch(_){}
    try{fs.unlinkSync(zipPath);}catch(_){}
  }
});
app.get('/api/admin/json-backup/download', async (req,res) => {
  if(!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  if(!ENABLE_JSON_BACKUP) return res.status(403).json({ok:false,error:'JSON backup is disabled.'});
  try {
    const config=githubConfig();
    if(!config) return res.status(503).json({ok:false,error:'GitHub backup is not configured.'});
    const content=await githubReadRepositoryText('backup/manifest.json');
    if(!content) return res.status(404).json({ok:false,error:'No verified GitHub JSON backup is available yet.'});
    const manifest=JSON.parse(content);
    if(manifest.verificationStatus!=='verified' || !manifest.archivePath || !manifest.archiveSha256) return res.status(409).json({ok:false,error:'The latest GitHub backup has not passed verification.'});
    const safeArchivePath=String(manifest.archivePath);
    if(!/^backup\/versions\/[A-Za-z0-9T._-]+\/SOV_Engineering_JSON_Backup_[A-Za-z0-9_-]+\.zip$/.test(safeArchivePath)) return res.status(400).json({ok:false,error:'The backup manifest contains an invalid archive path.'});
    const filename=path.basename(safeArchivePath);
    await githubStreamRepositoryFileToResponse(safeArchivePath,res,filename,manifest.archiveSha256);
  } catch(error) {
    console.error('GitHub JSON backup download failed:',error.message,error.stack||'');
    if(!res.headersSent) return res.status(502).json({ok:false,error:'The verified GitHub backup could not be downloaded.',detail:error.message});
  }
});

app.post('/api/admin/csv-sync', async (req,res) => {
  const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if(!auth) return;
  let syncStage = 'preflight';
  try {
    // This endpoint is the explicit Admin-approved sync path. Fail before
    // touching the pending buffer if encryption or the private GitHub target
    // is not configured; never silently treat a local-only write as success.
    encryptionKey();
    const config = githubConfig();
    if (!config) {
      throw new Error('GitHub CSV storage is not configured. Check GITHUB_TOKEN and GITHUB_REPO (or GITHUB_OWNER plus GITHUB_REPO).');
    }
    if (!config.branch || !config.basePath) {
      throw new Error('GitHub CSV storage configuration is incomplete. Check GITHUB_BRANCH and GITHUB_CSV_PATH.');
    }
    syncStage = 'pending-state-load';
    const result=await synchronizeDataOnAdminLogin();
    return res.json({ok:true,noOp:result?.noOp===true,pendingCount:result?.pendingCount||0});
  } catch(error){
    const detail = safeString(error?.message || error || 'Unknown synchronization error');
    console.error(`[Admin CSV synchronization failed; stage=${syncStage}; role=${safeString(auth.role)}]`, detail, error?.stack || '');
    return res.status(500).json({
      ok:false,
      error:'CSV synchronization failed. Pending JSON data was preserved.',
      detail,
      stage:syncStage
    });
  }
});

app.post('/api/auth/dashboard', async (req, res) => {
  try {
    const pin=safeString(req.body?.pin).trim();
    if(!pin) return res.status(400).json({ok:false,error:'PIN is required.'});
    if(!verifyCommonDashboardPin(pin)) return res.status(401).json({ok:false,error:'Incorrect PIN.'});
    return res.json({ok:true,role:'dashboard',token:createAuthToken({role:'dashboard'})});
  } catch (error) { return res.status(503).json({ok:false,error:'Common Dashboard PIN is not configured.'}); }
});

app.get('/api/login-employees', async (_req, res) => {
  try {
    const employees = await getEmployeesFromStore(false);
    return res.json({ok:true, employees:publicEmployees(employees).map(e=>({ ...e, loginRole:employeeRoleOf(e) }))});
  } catch (error) {
    return res.status(503).json({ok:false,error:'Employee login data is unavailable.'});
  }
});

/* ---------------------------------------------------------
 * Create employee - Employee ID is generated server-side
 * --------------------------------------------------------- */

app.get('/api/employees', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  try {
    const employees = await getEmployeesFromStore(false);
    return res.json({ ok: true, employees: publicEmployees(employees) });
  } catch (error) {
    console.error('Employee read failed:', error.message);
    return res.status(503).json({ ok: false, error: 'Employee data is unavailable.' });
  }
});

app.post('/api/auth/worker', async (req, res) => {
  try {
    const workerKey = safeString(req.body?.employeeId || req.body?.employeeCode || req.body?.code || req.body?.workerKey).trim();
    const enteredPin = safeString(req.body?.pin).trim();
    if (!workerKey || !enteredPin) return res.status(400).json({ ok: false, error: 'Worker and PIN are required.' });

    const employees = await getEmployeesFromStore(false);
    const worker = employees.find(e => employeeActiveOnDateServer(e) && ['WORKER','ADMIN_WORKER'].includes(employeeRoleOf(e)) && (
      employeeIdOf(e) === workerKey || employeeCodeOf(e) === workerKey || safeString(e.name).trim() === workerKey
    ));
    if (!worker) return res.status(401).json({ ok: false, error: 'Worker not found.' });

    const configuredHash = safeString(worker.pinHash).trim();
    if (!configuredHash) return res.status(401).json({ ok: false, error: 'No PIN is assigned to this employee. Ask Admin to set a PIN.' });

    const enteredHash = crypto.createHash('sha256').update(enteredPin, 'utf8').digest('hex');
    const configuredBuffer = Buffer.from(configuredHash, 'utf8');
    const enteredBuffer = Buffer.from(enteredHash, 'utf8');
    if (configuredBuffer.length !== enteredBuffer.length || !crypto.timingSafeEqual(configuredBuffer, enteredBuffer)) {
      return res.status(401).json({ ok: false, error: 'Incorrect PIN.' });
    }

    const role = 'worker';
    return res.json({ ok: true, worker: employeePublicView(worker), role, token:createAuthToken({role,employeeId:employeeIdOf(worker)}) });
  } catch (error) {
    console.error('Worker authentication failed:', error.message);
    return res.status(503).json({ ok: false, error: 'Worker authentication is unavailable.' });
  }
});

app.post('/api/employees', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  try {
    return await withEmployeeWriteLock(async () => {
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const name = safeString(body.name).trim();
      if (!name) return res.status(400).json({ ok: false, error: 'Employee Name is required.' });

      const details = { ...body };
      delete details.id;
      delete details.employeeId;
      details.name = name;
      details.loginRole = employeeRoleOf(details);
      details.relievingDate = validateRelievingDateServer(body.relievingDate);
      if (details.code == null && details.employeeCode != null) details.code = safeString(details.employeeCode);
      if (details.employeeCode == null && details.code != null) details.employeeCode = safeString(details.code);
      if (details.pinHash != null) details.pinHash = safeString(details.pinHash).trim();

      const result = await createEmployeeServerSide(details);
      return res.status(201).json({ ok: true, employee: result.employee, employees: result.employees });
    });
  } catch (error) {
    console.error('Employee creation failed:', error.message);
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/employees/:id/permanent-delete', async (req, res) => {
  const auth = requireAuth(req,res,['main_admin']);
  if (!auth) return;
  const mainAdminPin = safeString(req.body?.mainAdminPin).trim();
  if (!mainAdminPin) return res.status(400).json({ok:false,error:'Main Admin PIN is required.'});
  try {
    if (!verifyAdminPin(mainAdminPin)) return res.status(401).json({ok:false,error:'Main Admin PIN is incorrect.'});
    return await withEmployeeWriteLock(async () => {
      const id = safeString(req.params.id).trim();
      if (!id) return res.status(400).json({ok:false,error:'Employee ID is required.'});
      const employees = await getEmployeesFromStore(true);
      if (!employees.some(employee=>employeeIdOf(employee)===id&&!isDeleted(employee))) return res.status(404).json({ok:false,error:'Employee not found.'});
      const result = await updateEmployeeServerSide(id,{isDeleted:true,active:false,deletedAt:new Date().toISOString()});
      return res.json({ok:true,deletedEmployeeId:id,employees:result.employees});
    });
  } catch (error) {
    console.error('Verified employee deletion failed:', error.message);
    return res.status(error.statusCode||503).json({ok:false,error:'Employee could not be deleted. Please retry or contact the Main Admin.'});
  }
});

app.put('/api/employees/:id', async (req, res) => {
  const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if (!auth) return;
  try {
    return await withEmployeeWriteLock(async () => {
      const id = safeString(req.params.id).trim();
      if (!id) return res.status(400).json({ ok: false, error: 'Employee ID is required.' });
      const body = req.body && typeof req.body === 'object' ? { ...req.body } : {};
      if (body.isDeleted === true || body.active === false) return res.status(403).json({ ok:false, error:'Use the Main Admin verified deletion flow to remove an employee.' });
      delete body.id;
      delete body.employeeId;
      if (Object.prototype.hasOwnProperty.call(body,'relievingDate')) {
        const requestedRelievingDate = safeString(body.relievingDate).trim();
        const existingEmployees = await getEmployeesFromStore(true);
        const existingEmployee = existingEmployees.find(employee => employeeIdOf(employee) === id);
        const unchangedHistoricalDate = requestedRelievingDate && requestedRelievingDate === safeString(existingEmployee?.relievingDate).slice(0,10) && requestedRelievingDate < appTodayStr();
        body.relievingDate = unchangedHistoricalDate ? requestedRelievingDate : validateRelievingDateServer(requestedRelievingDate);
      }
      if (body.pinHash != null) body.pinHash = safeString(body.pinHash).trim();
      const result = await updateEmployeeServerSide(id, body);
      return res.json({ ok: true, employee: result.employee, employees: result.employees });
    });
  } catch (error) {
    console.error('Employee update failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

function normalizeInwardStatusServer(value){
  const v=safeString(value).trim();
  return ['Pending','Completed','Cancelled','Missing Parts'].includes(v) ? v : 'Pending';
}
function normalizePurchaseOrderStatusServer(value){
  const v=safeString(value).trim();
  return ['Pending','Completed','Cancelled','Missing Parts'].includes(v) ? v : 'Pending';
}

function bindAndValidatePendingPurchaseOrderWorkOrders(records, latestRecords){
  const incoming=Array.isArray(records)?records.map(r=>({...r})) : [];
  const latest=Array.isArray(latestRecords)?latestRecords:loadEntityAll('fl_workorders');
  const historical=loadEntityAll('fl_workhistory');
  const allKnownJobs=[...latest,...historical];
  const purchaseOrders=loadEntityAll('fl_invoices')
    .map(record=>normalizeInvoiceTransactionRecord(record))
    .filter(record=>!isDeleted(record) && safeString(record.type).trim().toUpperCase()==='PURCHASE ORDER');
  const poById=new Map(purchaseOrders.map(record=>[recordId(record),record]));
  const used=new Map();
  allKnownJobs.forEach(job=>{
    if(!job||isDeleted(job))return;
    if(normalizeWorkTypeServer(job.workType||job.works?.[0]?.workType)!=='PIECE')return;
    const poId=safeString(job.purchaseOrderId).trim(), itemId=safeString(job.purchaseOrderItemId).trim();
    if(poId&&itemId) used.set(`${poId}:${itemId}`,recordId(job));
  });
  const seenIncoming=new Map();
  for(const job of incoming){
    if(!job||job.isDeleted===true)continue;
    const type=normalizeWorkTypeServer(job.workType||job.works?.[0]?.workType);
    if(type!=='PIECE')continue;
    const poBased=job.purchaseOrderBased===true || String(job.workType||'').toUpperCase()==='PIECE_PO';
    const poId=safeString(job.purchaseOrderId).trim();
    const itemId=safeString(job.purchaseOrderItemId).trim();
    const existing=latest.find(x=>recordId(x)===recordId(job));
    if(!poBased){
      if(existing && !safeString(existing.purchaseOrderId).trim() && !safeString(existing.purchaseOrderItemId).trim()) continue;
      continue;
    }
    job.workType='PIECE';
    job.purchaseOrderBased=true;
    job.piecesBasedWithoutDc=false;
    job.customerDcNumber='';
    job.inwardId='';
    job.inwardItemId='';
    job.inwardItemName='';
    if(!poId||!itemId){
      if(existing && safeString(existing.purchaseOrderId).trim()===poId && safeString(existing.purchaseOrderItemId).trim()===itemId) continue;
      throw Object.assign(new Error('Purchase Order and Job selection are required for this Pieces Based Purchase Order Work Order.'),{statusCode:400});
    }
    const purchaseOrder=poById.get(poId);
    if(!purchaseOrder) throw Object.assign(new Error('Selected Purchase Order was not found.'),{statusCode:400});
    const items=Array.isArray(purchaseOrder.items)&&purchaseOrder.items.length ? purchaseOrder.items : [{itemId:safeString(purchaseOrder.itemId).trim() || `${poId}:item:0`,partName:purchaseOrder.partName,quantity:purchaseOrder.quantity}];
    const item=items.find((entry,index)=>safeString(entry?.itemId || entry?.id || `${poId}:item:${index}`).trim()===itemId);
    if(!item) throw Object.assign(new Error('Selected Job does not belong to the selected Purchase Order.'),{statusCode:400});
    const quantity=Number(item.quantity);
    if(!Number.isFinite(quantity)||quantity<=0) throw Object.assign(new Error('Selected Purchase Order Job has an invalid Quantity.'),{statusCode:400});
    const sameExistingLink=existing&&safeString(existing.purchaseOrderId).trim()===poId&&safeString(existing.purchaseOrderItemId).trim()===itemId;
    const status=normalizePurchaseOrderStatusServer(purchaseOrder.status);
    if(status!=='Pending'&&!sameExistingLink) throw Object.assign(new Error('Only Pending Purchase Order Jobs can be selected for a new Pieces Based Work Order.'),{statusCode:400});
    const key=`${poId}:${itemId}`;
    const owner=used.get(key);
    if(owner&&String(owner)!==String(recordId(job))&&!sameExistingLink) throw Object.assign(new Error('This Purchase Order Job has already been used in a Work Order.'),{statusCode:409});
    const incomingOwner=seenIncoming.get(key);
    if(incomingOwner&&String(incomingOwner)!==String(recordId(job))) throw Object.assign(new Error('The same Purchase Order Job cannot be used more than once.'),{statusCode:409});
    seenIncoming.set(key,recordId(job));
    job.purchaseOrderId=poId;
    job.purchaseOrderItemId=itemId;
    job.purchaseOrderItemName=safeString(item.partName).trim();
    job.customerPoNumber=safeString(purchaseOrder.customerPoNumber || purchaseOrder.number).trim();
    job.total=quantity;
    job.totalPieces=quantity;
  }
  return incoming;
}

function bindAndValidatePendingInwardWorkOrders(records, latestRecords){
  const incoming=Array.isArray(records)?records.map(r=>({...r})) : [];
  const latest=Array.isArray(latestRecords)?latestRecords:loadEntityAll('fl_workorders');
  const historical=loadEntityAll('fl_workhistory');
  const allKnownJobs=[...latest,...historical];
  const invoices=loadEntityAll('fl_invoices')
    .map(record=>normalizeInvoiceTransactionRecord(record))
    .filter(record=>!isDeleted(record) && safeString(record.type).trim().toUpperCase()==='INWARD');
  const invoiceById=new Map(invoices.map(record=>[recordId(record),record]));
  const used=new Map();
  allKnownJobs.forEach(job=>{
    if(!job||isDeleted(job))return;
    if(normalizeWorkTypeServer(job.workType||job.works?.[0]?.workType)!=='PIECE')return;
    const inwardId=safeString(job.inwardId).trim(), itemId=safeString(job.inwardItemId).trim();
    if(inwardId&&itemId) used.set(`${inwardId}:${itemId}`,recordId(job));
  });
  const seenIncoming=new Map();
  for(const job of incoming){
    if(!job||job.isDeleted===true)continue;
    const type=normalizeWorkTypeServer(job.workType||job.works?.[0]?.workType);
    if(type!=='PIECE')continue;
    const inwardId=safeString(job.inwardId).trim();
    const itemId=safeString(job.inwardItemId).trim();
    const standalonePieces=job.piecesBasedWithoutDc===true || String(job.workType||'').toUpperCase()==='PIECE_NO_DC';
    const purchaseOrderPieces=job.purchaseOrderBased===true || String(job.workType||'').toUpperCase()==='PIECE_PO';
    const existing=latest.find(x=>recordId(x)===recordId(job));
    if(standalonePieces||purchaseOrderPieces){
      if(purchaseOrderPieces){
        job.workType='PIECE';
        job.purchaseOrderBased=true;
        job.piecesBasedWithoutDc=false;
        job.customerDcNumber='';
        job.inwardId='';
        job.inwardItemId='';
        job.inwardItemName='';
      }
      if(standalonePieces){
      job.workType='PIECE';
      job.piecesBasedWithoutDc=true;
      job.customerDcNumber='';
      job.inwardId='';
      job.inwardItemId='';
      job.inwardItemName='';
      }
      continue;
    }
    if(!inwardId&&!itemId){
      // Preserve older legacy/manual Pieces Based records that already exist without an Inwards link.
      if(existing && !safeString(existing.inwardId).trim() && !safeString(existing.inwardItemId).trim()) continue;
      throw Object.assign(new Error('Pending Inwards Customer DC Number and Job selection are required for this Pieces Based Work Order.'),{statusCode:400});
    }
    if(!inwardId||!itemId) throw Object.assign(new Error('Pending Inwards Customer DC Number and Job selection are required for this Pieces Based Work Order.'),{statusCode:400});
    const inward=invoiceById.get(inwardId);
    if(!inward) throw Object.assign(new Error('Selected Pending Inwards record was not found.'),{statusCode:400});
    const items=Array.isArray(inward.items)&&inward.items.length ? inward.items : [{itemId:safeString(inward.itemId).trim() || `${inwardId}:item:0`,partName:inward.partName,quantity:inward.quantity}];
    const item=items.find((entry,index)=>safeString(entry?.itemId || entry?.id || `${inwardId}:item:${index}`).trim()===itemId);
    if(!item) throw Object.assign(new Error('Selected Job does not belong to the selected Inwards record.'),{statusCode:400});
    const expectedDc=safeString(inward.customerDcNumber || inward.dcNumber || inward.number).trim();
    const submittedDc=safeString(job.customerDcNumber).trim();
    if(submittedDc && expectedDc && submittedDc!==expectedDc) throw Object.assign(new Error('Selected Job does not belong to the selected Customer DC Number.'),{statusCode:400});
    const quantity=Number(item.quantity);
    if(!Number.isFinite(quantity)||quantity<=0) throw Object.assign(new Error('Selected Pending Inwards Job has an invalid Quantity.'),{statusCode:400});
    const sameExistingLink=existing&&safeString(existing.inwardId).trim()===inwardId&&safeString(existing.inwardItemId).trim()===itemId;
    const status=normalizeInwardStatusServer(inward.status);
    if(status!=='Pending'&&!sameExistingLink) throw Object.assign(new Error('Only Pending Inwards Jobs can be selected for a new Pieces Based Work Order.'),{statusCode:400});
    const key=`${inwardId}:${itemId}`;
    const owner=used.get(key);
    if(owner&&String(owner)!==String(recordId(job))&&!sameExistingLink) throw Object.assign(new Error('This Pending Inwards Job has already been used in a Work Order.'),{statusCode:409});
    const incomingOwner=seenIncoming.get(key);
    if(incomingOwner&&String(incomingOwner)!==String(recordId(job))) throw Object.assign(new Error('The same Pending Inwards Job cannot be used more than once.'),{statusCode:409});
    seenIncoming.set(key,recordId(job));
    job.customerDcNumber=safeString(inward.customerDcNumber || inward.dcNumber || inward.number).trim();
    job.inwardId=inwardId;
    job.inwardItemId=itemId;
    job.inwardItemName=safeString(item.partName).trim();
    // Server is authoritative for the Pieces Based common total.
    job.total=quantity;
    job.totalPieces=quantity;
  }
  return incoming;
}

function normalizeWorkTypeServer(value){
  const v=safeString(value).trim().toUpperCase();
  if(v==='NO_FIXED'||v==='NO_FIXED_TOTAL'||v==='VARIABLE')return 'NO_FIXED';
  if(v==='WORK_BASED'||v==='NOT_APPLICABLE'||v==='COUNT_NOT_APPLICABLE')return 'WORK_BASED';
  return 'PIECE';
}

function workOrderProgressServer(job){
  const explicitParts=Array.isArray(job?.parts)?job.parts.filter(p=>p&&typeof p==='object'):[];
  let total=0, completed=0;
  if(explicitParts.length){
    for(const part of explicitParts){
      const partTotal=Number(part.quantity ?? part.total ?? part.totalPieces);
      if(!Number.isFinite(partTotal)||partTotal<=0) continue;
      const partCompleted=Math.max(0,Math.min(partTotal,Number(part.completed ?? part.completedPieces ?? 0)||0));
      total+=partTotal; completed+=partCompleted;
    }
  }else{
    const pieceWorks=Array.isArray(job?.works)?job.works.filter(w=>normalizeWorkTypeServer(w?.workType)==='PIECE'):[];
    const seen=new Set();
    for(const work of pieceWorks){
      const workId=safeString(work?.id).trim();
      const key=workId || `__work_${seen.size}`;
      if(seen.has(key)) continue;
      seen.add(key);
      const workTotal=workTotalRequired(job,work);
      if(!Number.isFinite(workTotal)||workTotal<=0) continue;
      const workCompleted=Math.max(0,Math.min(workTotal,Number(work?.completed||0)));
      total+=workTotal; completed+=workCompleted;
    }
  }
  completed=Math.min(total,Math.max(0,completed));
  const completedPct=total>0?Math.min(100,Math.round((completed/total)*100)):0;
  return {total,completed,remaining:Math.max(0,total-completed),completedPct,remainingPct:Math.max(0,100-completedPct)};
}

function workOrderCompletedForRestore(job){
  if (!job || safeString(job.status).trim().toUpperCase()==='DONE' || safeString(job.archivedReason).trim().toLowerCase()==='done') return true;
  const progress=workOrderProgressServer(job);
  if (progress.total>0 && progress.completed>=progress.total) return true;
  const works=Array.isArray(job.works)?job.works:[];
  if(!works.length) return false;
  return works.every(work=>{
    if(normalizeWorkTypeServer(work?.workType)==='PIECE'){
      const total=workTotalRequired(job,work);
      return safeString(work?.status).trim().toUpperCase()==='DONE' || (total>0 && Number(work?.completed||0)>=total);
    }
    const assigned=assignedIdsServer(work).map(String).filter(Boolean);
    if(!assigned.length) return false;
    return assigned.every(employeeId=>{
      const hasCount=Object.keys(work?.dailyCompleted||{}).some(key=>String(key).endsWith(':'+employeeId));
      const hasWorked=Object.entries(work?.workDayRecords||{}).some(([key,value])=>String(key).endsWith(':'+employeeId)&&value?.worked===true);
      const hasHistory=(Array.isArray(work?.completionHistory)&&work.completionHistory.some(item=>String(item?.employeeId||'')===employeeId))
        || (Array.isArray(work?.correctionHistory)&&work.correctionHistory.some(item=>String(item?.employeeId||'')===employeeId&&item?.worked===true));
      return hasCount||hasWorked||hasHistory;
    });
  });
}

function validatePendingInwardCompletion(incomingRecords, latestRecords){
  const incoming=Array.isArray(incomingRecords)?incomingRecords:[];
  const latest=Array.isArray(latestRecords)?latestRecords:loadEntityAll('fl_invoices');
  const latestById=new Map(latest.map(r=>[recordId(r),r]));
  const candidateById=new Map(incoming.map(r=>[recordId(r),normalizeInvoiceTransactionRecord(r)]));
  const changedDcs=new Set();
  for(const record of candidateById.values()){
    if(safeString(record.type).trim().toUpperCase()!=='INWARD'||isDeleted(record)) continue;
    const old=latestById.get(recordId(record));
    if(old && normalizeInwardStatusServer(old.status)==='Pending' && normalizeInwardStatusServer(record.status)==='Completed'){
      const dc=safeString(record.customerDcNumber || record.dcNumber || record.number).trim();
      if(dc) changedDcs.add(dc);
    }
  }
  if(!changedDcs.size) return;

  const invoices=[...candidateById.values()].filter(r=>!isDeleted(r)&&safeString(r.type).trim().toUpperCase()==='INWARD');
  const jobs=[...loadEntityAll('fl_workorders'),...loadEntityAll('fl_workhistory')].filter(j=>j&&!isDeleted(j));
  for(const dc of changedDcs){
    const dcInwards=invoices.filter(r=>{
      if(safeString(r.customerDcNumber || r.dcNumber || r.number).trim()!==dc) return false;
      const old=latestById.get(recordId(r));
      const oldStatus=old?normalizeInwardStatusServer(old.status):normalizeInwardStatusServer(r.status);
      return oldStatus==='Pending';
    });
    const entries=[];
    for(const inward of dcInwards){
      const items=Array.isArray(inward.items)&&inward.items.length ? inward.items : [{itemId:safeString(inward.itemId).trim() || `${recordId(inward)}:item:0`,partName:inward.partName,quantity:inward.quantity}];
      for(let index=0;index<items.length;index++){
        const item=items[index]||{};
        const itemId=safeString(item.itemId || item.id || `${recordId(inward)}:item:${index}`).trim();
        const quantity=Number(item.quantity);
        if(!itemId||!Number.isFinite(quantity)||quantity<=0) throw Object.assign(new Error(`Customer DC Number ${dc} cannot be marked Completed because an Inwards Job has invalid quantity data.`),{statusCode:400});
        entries.push({inwardId:recordId(inward),itemId});
      }
    }
    if(!entries.length) throw Object.assign(new Error(`Customer DC Number ${dc} cannot be marked Completed because no Jobs were found.`),{statusCode:400});
    for(const entry of entries){
      const source=jobs.find(job=>safeString(job.inwardId).trim()===entry.inwardId&&safeString(job.inwardItemId).trim()===entry.itemId);
      if(!source) throw Object.assign(new Error(`Customer DC Number ${dc} cannot be marked Completed because a Job has no linked Work Order.`),{statusCode:400});
      const progress=workOrderProgressServer(source);
      if(Number(progress.completedPct)!==100||Number(progress.remainingPct)!==0){
        throw Object.assign(new Error(`Customer DC Number ${dc} cannot be marked Completed until every Job is 100% complete. Current Job completion is ${progress.completedPct}%.`),{statusCode:400});
      }
    }
  }
}

function validatePendingPurchaseOrderCompletion(incomingRecords, latestRecords){
  const incoming=Array.isArray(incomingRecords)?incomingRecords:[];
  const latest=Array.isArray(latestRecords)?latestRecords:loadEntityAll('fl_invoices');
  const latestById=new Map(latest.map(r=>[recordId(r),r]));
  const candidateById=new Map(incoming.map(r=>[recordId(r),normalizeInvoiceTransactionRecord(r)]));
  const changedPos=new Set();
  for(const record of candidateById.values()){
    if(safeString(record.type).trim().toUpperCase()!=='PURCHASE ORDER'||isDeleted(record)) continue;
    const old=latestById.get(recordId(record));
    if(old && normalizePurchaseOrderStatusServer(old.status)==='Pending' && normalizePurchaseOrderStatusServer(record.status)==='Completed') changedPos.add(recordId(record));
  }
  if(!changedPos.size) return;
  const jobs=[...loadEntityAll('fl_workorders'),...loadEntityAll('fl_workhistory')].filter(j=>j&&!isDeleted(j));
  for(const poId of changedPos){
    const po=candidateById.get(poId);
    if(!po) continue;
    const items=Array.isArray(po.items)&&po.items.length ? po.items : [{itemId:safeString(po.itemId).trim() || `${poId}:item:0`,partName:po.partName,quantity:po.quantity}];
    if(!items.length) throw Object.assign(new Error(`Purchase Order ${safeString(po.customerPoNumber || po.number)} cannot be marked Completed because no Jobs were found.`),{statusCode:400});
    for(let index=0;index<items.length;index++){
      const item=items[index]||{};
      const itemId=safeString(item.itemId || item.id || `${poId}:item:${index}`).trim();
      const quantity=Number(item.quantity);
      if(!itemId||!Number.isFinite(quantity)||quantity<=0) throw Object.assign(new Error(`Purchase Order ${safeString(po.customerPoNumber || po.number)} cannot be marked Completed because a Job has invalid quantity data.`),{statusCode:400});
      const source=jobs.find(job=>safeString(job.purchaseOrderId).trim()===poId&&safeString(job.purchaseOrderItemId).trim()===itemId);
      if(!source) throw Object.assign(new Error(`Purchase Order ${safeString(po.customerPoNumber || po.number)} cannot be marked Completed because a Job has no linked Work Order.`),{statusCode:400});
      const progress=workOrderProgressServer(source);
      if(Number(progress.completedPct)!==100||Number(progress.remainingPct)!==0) throw Object.assign(new Error(`Purchase Order ${safeString(po.customerPoNumber || po.number)} cannot be marked Completed until every Job is 100% complete. Current Job completion is ${progress.completedPct}%.`),{statusCode:400});
    }
  }
}

function validateWorkOrderRecords(records) {
  for (const job of Array.isArray(records) ? records : []) {
    if (!job || job.isDeleted === true) continue;
    const works = Array.isArray(job.works) ? job.works : [];
    if (!works.length) throw new Error('A Work Order must contain at least one Work.');
    const type = String(job.workType || works[0]?.workType || 'PIECE').toUpperCase();
    if (type === 'PIECE') {
      if (!safeString(job.image).trim()) throw new Error('Work Image is required for Pieces Based work.');
      const total = Number(job.total ?? job.totalPieces ?? 0);
      if (!Number.isFinite(total) || total <= 0) throw new Error('Total Pieces Required is required for Pieces Based work.');
      if (works.some(w => String(w.workType || 'PIECE').toUpperCase() !== 'PIECE')) throw new Error('Pieces Based works must use the Pieces Based Work Type.');
    } else if (type === 'NO_FIXED') {
      if (works.length !== 1) throw new Error('No Fixed Total Pieces allows only one Work.');
      if (safeString(job.image).trim()) throw new Error('Work Image is not applicable for No Fixed Total Pieces.');
      if (job.total != null || job.totalPieces != null) throw new Error('Total Pieces Required is not applicable for No Fixed Total Pieces.');
    } else if (type === 'WORK_BASED') {
      if (works.length !== 1) throw new Error('Count Not Applicable / Work-Based allows only one Work.');
      if (safeString(job.image).trim()) throw new Error('Work Image is not applicable for Count Not Applicable / Work-Based.');
      if (job.total != null || job.totalPieces != null) throw new Error('Total Pieces Required is not applicable for Count Not Applicable / Work-Based.');
    }
  }
}

/* ---------------------------------------------------------
 * Live data update events and serialized entity writes
 * --------------------------------------------------------- */
const sseClients = new Set();
const entityWriteLocks = new Map();

function broadcastDataUpdated(key, ids=[]){
  const uniqueIds=[...new Set((Array.isArray(ids)?ids:[]).map(value=>safeString(value).trim()).filter(Boolean))];
  // An empty ID list intentionally tells clients to use the safe collection fallback.
  const changedIds=uniqueIds.length>100?[]:uniqueIds;
  const payload=`event: data-updated\ndata: ${JSON.stringify({key,ids:changedIds,updatedAt:new Date().toISOString()})}\n\n`;
  for(const client of sseClients){
    try{ client.write(payload); }catch(e){ try{ client.end(); }catch(_e){} sseClients.delete(client); }
  }
}

async function withEntityWriteLock(key, fn){
  const previous=entityWriteLocks.get(key)||Promise.resolve();
  let release;
  const current=new Promise(resolve=>{release=resolve;});
  entityWriteLocks.set(key,current);
  await previous;
  try{ return await fn(); }
  finally{
    release();
    if(entityWriteLocks.get(key)===current) entityWriteLocks.delete(key);
  }
}

function mergeNestedWorkRecord(oldWork, incomingWork){
  const merged={...(oldWork||{}),...(incomingWork||{})};
  // A partial/legacy request that omits assignedTo must not clear an existing
  // assignment. An explicit empty array remains an intentional unassignment;
  // the current editor also preserves IDs for workers absent from its checklist.
  if (incomingWork?.assignedTo == null && Array.isArray(oldWork?.assignedTo) && oldWork.assignedTo.length) {
    merged.assignedTo = [...oldWork.assignedTo];
  }
  delete merged.__assignmentsExplicit;
  if(oldWork?.dailyCompleted || incomingWork?.dailyCompleted || incomingWork?.dailyCompletedDeletions){
    const daily={...(oldWork?.dailyCompleted||{}),...(incomingWork?.dailyCompleted||{})};
    for(const key of (Array.isArray(incomingWork?.dailyCompletedDeletions)?incomingWork.dailyCompletedDeletions:[])) delete daily[String(key)];
    for(const [key,value] of Object.entries(daily)) if(!Number.isFinite(Number(value)) || Number(value)<=0) delete daily[key];
    merged.dailyCompleted=daily;
  }
  if(oldWork?.workDayRecords || incomingWork?.workDayRecords || incomingWork?.workDayRecordDeletions){
    const records={...(oldWork?.workDayRecords||{}),...(incomingWork?.workDayRecords||{})};
    for(const key of (Array.isArray(incomingWork?.workDayRecordDeletions)?incomingWork.workDayRecordDeletions:[])) delete records[String(key)];
    const allowsZeroHourCountRecord = normalizeWorkTypeServer(merged.workType) === 'NO_FIXED';
    for(const [key,value] of Object.entries(records)) {
      const hours=Number(value?.hours);
      const validNoFixedCount=allowsZeroHourCountRecord && Number.isFinite(Number(value?.count)) && Number(value.count)>=0 && Number.isFinite(hours) && hours===0;
      if(!value || value.worked!==true || !Number.isFinite(hours) || (hours<=0 && !validNoFixedCount)) delete records[key];
    }
    merged.workDayRecords=records;
  }
  const markers=[...(oldWork?.notWorkedRecords||[]),...(incomingWork?.notWorkedRecords||[])];
  if(markers.length || incomingWork?.notWorkedRecordDeletions){ const byKey=new Map(); markers.forEach(x=>{if(x?.employeeId!=null&&x?.date)byKey.set(`${x.date}:${x.employeeId}`,{...x});}); for(const key of (Array.isArray(incomingWork?.notWorkedRecordDeletions)?incomingWork.notWorkedRecordDeletions:[])) byKey.delete(String(key)); merged.notWorkedRecords=[...byKey.values()]; }
  let oldCompletionHistory=[...(oldWork?.completionHistory||[])]; const replacements=Array.isArray(incomingWork?.completionHistoryReplacements)?incomingWork.completionHistoryReplacements.map(String):[]; if(replacements.length) oldCompletionHistory=oldCompletionHistory.filter(x=>!replacements.includes(`${x?.date}:${x?.employeeId}`)); const history=[...oldCompletionHistory,...(incomingWork?.completionHistory||[])];
  if(history.length){ const byId=new Map(); history.forEach(x=>{if(x?.id)byId.set(String(x.id),x);}); merged.completionHistory=[...byId.values()]; }
  const adjustments=[...(oldWork?.adminCountAdjustments||[]),...(incomingWork?.adminCountAdjustments||[])];
  if(adjustments.length){ const byId=new Map(); adjustments.forEach(x=>{if(x?.id)byId.set(String(x.id),x);}); merged.adminCountAdjustments=[...byId.values()]; }
  return merged;
}

function adminAdjustmentsForWork(work) {
  let adjustments = Array.isArray(work?.adminCountAdjustments) ? work.adminCountAdjustments.map(x => ({ ...x })) : [];
  const hasLegacy = work?.adminCompletedOverride !== undefined && work?.adminCompletedOverride !== null && work?.adminCompletedOverride !== '';
  if (hasLegacy && !adjustments.length) {
    const dailyTotal = Object.entries(work?.dailyCompleted || {})
      .filter(([key]) => !String(key).endsWith(':__ADMIN__'))
      .reduce((sum, [, value]) => sum + Math.max(0, Number(value || 0)), 0);
    const legacyTarget = Math.max(0, Number(work.adminCompletedOverride || 0));
    adjustments.push({
      id: 'legacy-admin-' + safeString(work.id),
      date: appTodayStr(),
      employeeId: '__ADMIN_LEGACY__',
      delta: legacyTarget - dailyTotal,
      finalCount: legacyTarget,
      createdAt: Date.now(),
      legacy: true
    });
  }
  return adjustments;
}

function workTotalRequired(job, work) {
  const own = Number(work?.total ?? work?.totalPieces);
  if (Number.isFinite(own) && own > 0) return own;
  const shared = Number(job?.total ?? job?.totalPieces);
  return Number.isFinite(shared) && shared > 0 ? shared : 0;
}

function workCompletedBase(work) {
  const dailyTotal = Object.entries(work?.dailyCompleted || {})
    .filter(([key]) => !String(key).endsWith(':__ADMIN__'))
    .reduce((sum, [, value]) => sum + Math.max(0, Number(value || 0)), 0);
  const historyTotal = Array.isArray(work?.completionHistory)
    ? work.completionHistory
        .filter(item => String(item?.employeeId || '') !== '__ADMIN__' && String(item?.employeeId || '') !== '__ADMIN_LEGACY__')
        .reduce((sum, item) => sum + Math.max(0, Number(item?.pieces || 0)), 0)
    : 0;
  return dailyTotal > 0 ? dailyTotal : historyTotal > 0 ? historyTotal : Math.max(0, Number(work?.completed || 0));
}

function reconcileWorkOrderDerivedFields(job) {
  const out = { ...job, works: Array.isArray(job.works) ? job.works.map(w => ({ ...w })) : [] };
  out.works = out.works.map(w => {
    const x = { ...w };
    const type = String(x.workType || 'PIECE').toUpperCase();
    if (type === 'PIECE') {
      const total = workTotalRequired(out, x);
      const base = workCompletedBase(x);
      const adjustments = adminAdjustmentsForWork(x);
      const adminDelta = adjustments.reduce((sum, item) => sum + Number(item?.delta || 0), 0);
      x.adminCountAdjustments = adjustments;
      delete x.adminCompletedOverride;
      x.completed = Math.max(0, Math.min(total, base + adminDelta));
      x.remaining = Math.max(0, total - x.completed);
      x.status = x.completed >= total && total > 0 ? 'DONE' : 'ACTIVE';
    } else {
      delete x.remaining;
    }
    return x;
  });
  // Reaching completion at Work level does not close the Job.
  // The Job remains active until Admin explicitly confirms Done/archive.
  if (!out.isDeleted && !out.archived) out.status = 'ACTIVE';
  return out;
}

function validateWorkOrderCounts(records) {
  for (const job of Array.isArray(records) ? records : []) {
    if (!job || job.isDeleted === true) continue;
    for (const work of Array.isArray(job.works) ? job.works : []) {
      if (String(work.workType || 'PIECE').toUpperCase() !== 'PIECE') continue;
      const total = workTotalRequired(job, work);
      if (!Number.isFinite(total) || total <= 0) continue;
      const base = workCompletedBase(work);
      const adminDelta = adminAdjustmentsForWork(work).reduce((sum, item) => sum + Number(item?.delta || 0), 0);
      const resulting = base + adminDelta;
      if (resulting > total) throw new Error(`Completed quantity cannot exceed the Work's Total Pieces Required (${total}).`);
      if (resulting < 0) throw new Error('Completed quantity cannot be negative.');
    }
  }
}

function validateWorkOrderCountsBeforeReconcile(records) {
  for (const job of Array.isArray(records) ? records : []) {
    if (!job || job.isDeleted === true) continue;
    for (const work of Array.isArray(job.works) ? job.works : []) {
      if (String(work.workType || 'PIECE').toUpperCase() !== 'PIECE') continue;
      const total = workTotalRequired(job, work);
      if (!Number.isFinite(total) || total <= 0) continue;
      const base = workCompletedBase(work);
      const adminDelta = adminAdjustmentsForWork(work).reduce((sum, item) => sum + Number(item?.delta || 0), 0);
      const resulting = base + adminDelta;
      if (resulting > total) throw new Error(`Completed quantity cannot exceed this Work's remaining quantity. Stored total=${total}, resulting completed=${resulting}.`);
      if (resulting < 0) throw new Error('Completed quantity cannot be negative.');
    }
  }
}

function normalizeInvoiceTransactionRecord(record) {
  const input = normalizeIsDeleted({ ...(record || {}) });
  const type = safeString(input.type).trim().toUpperCase();
  if (type === 'PURCHASE ORDER') {
    input.type = 'Purchase Order';
    input.documentType = 'Purchase Order';
    input.customerPoNumber = safeString(input.customerPoNumber || input.number).trim();
    input.number = ''; input.invoiceNumber = ''; input.dcNumber = '';
    input.customerDcNumber = ''; input.method = ''; input.vehicleNumber = '';
    input.status = normalizePurchaseOrderStatusServer(input.status);
    delete input.gstPercentage; delete input.paymentStatus; delete input.subtotal; delete input.gstAmount; delete input.totalAmount;
    return input;
  }
  if (type === 'INWARD') {
    input.type = 'Inward';
    input.documentType = 'Invoice';
    input.invoiceNumber = safeString(input.invoiceNumber || input.number).trim();
    input.dcNumber = safeString(input.dcNumber).trim();
    input.number = input.invoiceNumber;
    input.customerPoNumber = '';
    input.customerDcNumber = safeString(input.customerDcNumber || input.customerDc || '').trim();
    input.status = normalizeInwardStatusServer(input.status);
    input.method = safeString(input.method).trim();
    input.vehicleNumber = safeString(input.vehicleNumber).trim();
    return input;
  }
  if (type === 'OUTWARD') {
    input.type = 'Outward';
    input.customerPoNumber = ''; input.invoiceNumber = ''; input.dcNumber = '';
  }
  return input;
}

function mergeEntityRecord(entity, oldRecord, incomingRecord){
  if(entity!=='fl_workorders') return entity === 'fl_attendance'
    ? mergeAttendanceRecord(oldRecord, incomingRecord)
    : normalizeIsDeleted({...(oldRecord||{}),...(incomingRecord||{})});
  const replaceWorks = incomingRecord?.__replaceWorks === true;
  const merged=normalizeIsDeleted({...(oldRecord||{}),...(incomingRecord||{})});
  delete merged.__replaceWorks;
  const oldWorks=Array.isArray(oldRecord?.works)?oldRecord.works:[];
  const incomingWorks=Array.isArray(incomingRecord?.works)?incomingRecord.works:[];
  const byId=new Map();
  if(!replaceWorks){
    oldWorks.filter(w=>w&&recordId(w)).forEach(w=>byId.set(recordId(w),{...w}));
  }
  incomingWorks.filter(w=>w&&recordId(w)).forEach(w=>{
    const id=recordId(w);
    byId.set(id,mergeNestedWorkRecord(replaceWorks ? oldWorks.find(old=>recordId(old)===id) : byId.get(id),w));
  });
  if(oldRecord?.works || incomingRecord?.works) merged.works=[...byId.values()];
  return reconcileWorkOrderDerivedFields(merged);
}

app.get('/api/events', (req,res)=>{
  // SSE must authenticate through the normal Authorization header. The client
  // uses fetch-streaming so credentials do not have to be placed in the URL.
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker','dashboard'])) return;
  res.setHeader('Content-Type','text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control','no-cache, no-transform');
  res.setHeader('Connection','keep-alive');
  res.setHeader('X-Accel-Buffering','no');
  res.flushHeaders?.();
  res.write(`event: connected\ndata: ${JSON.stringify({ok:true})}\n\n`);
  sseClients.add(res);
  let cleaned=false;
  const cleanup=()=>{
    if(cleaned) return;
    cleaned=true;
    clearInterval(heartbeat);
    sseClients.delete(res);
  };
  const heartbeat=setInterval(()=>{
    if(res.destroyed || res.writableEnded){cleanup();return;}
    try{res.write(': heartbeat\n\n');}catch(e){cleanup();try{res.end();}catch(_) {}}
  },25000);
  // Listen on the response/socket lifecycle, not only req.close: a GET request
  // body can complete before an SSE response is meant to end.
  res.on('close',cleanup);
  res.on('error',cleanup);
  req.on('aborted',cleanup);
});


/* ---------------------------------------------------------
 * Entire Work Order / Job edit
 *
 * The frontend already calls PUT /api/workorders/:jobId/edit. Keep that
 * contract intact and perform a server-side merge against the latest saved
 * job so edits cannot reset progress/history. __replaceWorks is an internal
 * marker used only for this explicit Entire Job Edit operation: it allows
 * the user's deliberate add/remove Work changes while still merging every
 * unchanged nested Work record with the latest persisted version.
 * --------------------------------------------------------- */
app.put('/api/workorders/:jobId/edit', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  if (!jobId) return res.status(400).json({ ok:false, error:'Work Order ID is required.' });

  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const latestOrders = loadEntityAll('fl_workorders');
      const existing = latestOrders.find(record => recordId(record) === jobId);
      if (!existing || existing.isDeleted === true || existing.archived === true) {
        throw Object.assign(new Error('Work Order not found.'), { statusCode:404 });
      }

      const submitted = req.body?.job && typeof req.body.job === 'object' ? { ...req.body.job } : null;
      if (!submitted) throw Object.assign(new Error('Work Order data is required.'), { statusCode:400 });

      // Never allow the request to change the identity of the existing Job.
      submitted.id = jobId;
      submitted.__replaceWorks = true;
      delete submitted.createdAt;
      submitted.updatedAt = Date.now();
      submitted.isDeleted = false;
      submitted.active = existing.active !== false;

      const incomingWorks = Array.isArray(submitted.works) ? submitted.works : [];
      if (!incomingWorks.length) {
        throw Object.assign(new Error('A Work Order must contain at least one Work.'), { statusCode:400 });
      }

      const updated = mergeEntityRecord('fl_workorders', existing, submitted);
      updated.id = jobId;
      updated.createdAt = existing.createdAt;
      updated.updatedAt = Date.now();
      updated.isDeleted = false;
      updated.active = existing.active !== false;

      const inwardRebound=bindAndValidatePendingInwardWorkOrders([updated], latestOrders);
      const poRebound=bindAndValidatePendingPurchaseOrderWorkOrders(inwardRebound, latestOrders);
      const reboundJob=poRebound && poRebound[0] ? poRebound[0] : updated;
      validateWorkOrderRecords([reboundJob]);
      const writeResult = await writeEntityRecords('fl_workorders', [
        { ...reboundJob, __replaceWorks:true }
      ]);
      const saved = (Array.isArray(writeResult?.committedRecords) ? writeResult.committedRecords : []).find(record => recordId(record) === jobId) || updated;
      const expectedWorkIds = incomingWorks.filter(work => work && recordId(work)).map(recordId).sort();
      const savedWorkIds = (Array.isArray(saved?.works) ? saved.works : []).filter(work => work && recordId(work)).map(recordId).sort();
      if (expectedWorkIds.length !== savedWorkIds.length || expectedWorkIds.some((id, index) => id !== savedWorkIds[index])) {
        throw Object.assign(new Error('Saved Work list verification failed. The active Work list was not confirmed; please retry.'), { statusCode: 500 });
      }
      const savedWorkMap = new Map((Array.isArray(saved?.works) ? saved.works : []).map(work => [recordId(work), work]));
      for (const submittedWork of incomingWorks.filter(work => work && recordId(work))) {
        const persistedWork = savedWorkMap.get(recordId(submittedWork));
        if (!persistedWork) throw Object.assign(new Error(`Saved Work verification failed for ${recordId(submittedWork)}.`), { statusCode:500 });
        const requestedAssignments = Array.isArray(submittedWork.assignedTo) ? [...new Set(submittedWork.assignedTo.map(value => safeString(typeof value === 'object' ? (value.employeeId || value.id || value.value) : value).trim()).filter(Boolean))].sort() : null;
        const persistedAssignments = Array.isArray(persistedWork.assignedTo) ? [...new Set(persistedWork.assignedTo.map(value => safeString(typeof value === 'object' ? (value.employeeId || value.id || value.value) : value).trim()).filter(Boolean))].sort() : [];
        if (requestedAssignments && (requestedAssignments.length !== persistedAssignments.length || requestedAssignments.some((id, index) => id !== persistedAssignments[index]))) {
          throw Object.assign(new Error(`Saved employee assignment verification failed for Work ${recordId(submittedWork)}.`), { statusCode:500 });
        }
        const requestedTitle = safeString(submittedWork.title || submittedWork.workName).trim();
        const persistedTitle = safeString(persistedWork.title || persistedWork.workName).trim();
        if (requestedTitle && requestedTitle !== persistedTitle) {
          throw Object.assign(new Error(`Saved Work name verification failed for Work ${recordId(submittedWork)}.`), { statusCode:500 });
        }
      }
      for (const field of ['partName','instructions','date','image','total','totalPieces','workType','customerDcNumber','inwardId','inwardItemId','purchaseOrderId','purchaseOrderItemId']) {
        if (Object.prototype.hasOwnProperty.call(reboundJob, field) && !sameJsonValue(saved?.[field] ?? null, reboundJob[field] ?? null)) {
          throw Object.assign(new Error(`Saved Work Order verification failed for field ${field}.`), { statusCode:500 });
        }
      }
      return { writeResult, job: reconcileWorkOrderDerivedFields(saved || reboundJob) };
    });

    return res.json({ ok:true, job:result.job, workOrder:result.job, ...result.writeResult });
  } catch (error) {
    console.error('Entire Work Order edit failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Work order update failed.' });
  }
});

/* ---------------------------------------------------------
 * Worker final daily piece-count update
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/worker-count', async (req, res) => {
  const auth = requireAuth(req,res,['worker']);
  if (!auth) return;
  const jobId = safeString(req.params.jobId).trim();
  const workId = safeString(req.body?.workId).trim();
  const date = safeString(req.body?.date).trim();
  const finalCount = Number(req.body?.finalCount);
  const requestId = safeString(req.body?.requestId).trim();
  const employeeId = safeString(auth.employeeId).trim();

  if (!jobId || !workId || !employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(finalCount) || !Number.isInteger(finalCount) || finalCount < 0) {
    return res.status(400).json({ok:false,error:'Job, Work, Worker, valid date and non-negative whole count are required.'});
  }

  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || job.isDeleted === true || job.archived === true) {
        throw Object.assign(new Error('Work Order not found.'), {statusCode:404});
      }

      const work = Array.isArray(job.works) ? job.works.find(x => recordId(x) === workId) : null;
      if (!work || String(work.workType || 'PIECE').toUpperCase() !== 'PIECE') {
        throw Object.assign(new Error('Worker count updates apply only to Pieces Based work.'), {statusCode:400});
      }
      if (String(work.status || 'ACTIVE').toUpperCase() === 'DONE') {
        throw Object.assign(new Error('Completed Work count cannot be modified.'), {statusCode:403});
      }
      if (!assignedIdsServer(work).includes(employeeId)) {
        throw Object.assign(new Error('You are not assigned to this Work.'), {statusCode:403});
      }

      const total = workTotalRequired(job, work);
      if (!Number.isFinite(total) || total <= 0) {
        throw Object.assign(new Error('Work Total Pieces Required is missing.'), {statusCode:400});
      }
      if (finalCount > total) {
        throw Object.assign(new Error(`Completed quantity cannot exceed this Work's Total Pieces Required (${total}).`), {statusCode:400});
      }

      const key = `${date}:${employeeId}`;
      // Reject a stale browser submission instead of letting an older count
      // overwrite a more recent save from another tab/device. The client can
      // reload the current count and safely retry.
      if (req.body?.expectedDailyCount !== undefined) {
        const expected = Number(req.body.expectedDailyCount);
        const currentDaily = Math.max(0, Number((work.dailyCompleted || {})[key] || 0));
        if (!Number.isFinite(expected) || expected !== currentDaily) {
          throw Object.assign(new Error('This count changed after the page was loaded. Reload My Work to get the latest saved count, then try again.'), {statusCode:409});
        }
      }
      const adminAdjustment = adminCountAdjustmentForDateServer(work, date, employeeId);
      const directTarget = finalCount - adminAdjustment;
      if (directTarget < 0) {
        throw Object.assign(new Error('The requested worker count conflicts with an existing Admin count adjustment.'), {statusCode:400});
      }

      if (requestId && Array.isArray(work.workerCountHistory)) {
        const priorRequest = work.workerCountHistory.find(x => String(x?.requestId || '') === requestId);
        if (priorRequest) {
          if (String(priorRequest.employeeId || '') !== employeeId || String(priorRequest.date || '') !== date || Number(priorRequest.finalCount) !== finalCount) {
            throw Object.assign(new Error('This count request ID was already used for a different worker, date, or quantity. Reload My Work and retry.'), {statusCode:409});
          }
          const priorDirect = Math.max(0, Number((work.dailyCompleted || {})[key] || 0));
          const priorVerified = workCompletedForDateServer(work, date, employeeId) === finalCount &&
            (directTarget > 0 ? priorDirect === directTarget : priorDirect === 0 && (work.dailyCompletedDeletions || []).includes(key));
          if (!priorVerified) {
            throw Object.assign(new Error('This count request was already recorded, but its saved value no longer matches. Reload My Work before retrying.'), {statusCode:409});
          }
          return {job:reconcileWorkOrderDerivedFields(job), finalCount, date, employeeId, verified:true, duplicate:true};
        }
      }

      const updatedJob = {
        ...job,
        updatedAt: new Date().toISOString(),
        works: job.works.map(w => {
          if (recordId(w) !== workId) return w;
          const updated = {
            ...w,
            updatedAt: new Date().toISOString(),
            dailyCompleted: {...(w.dailyCompleted || {})},
            dailyCompletedDeletions: Array.isArray(w.dailyCompletedDeletions) ? [...w.dailyCompletedDeletions] : [],
            completionHistory: Array.isArray(w.completionHistory) ? w.completionHistory.filter(x => !(String(x?.date) === date && String(x?.employeeId) === employeeId)) : [],
            completionHistoryReplacements: Array.isArray(w.completionHistoryReplacements) ? [...w.completionHistoryReplacements] : [],
            workerCountHistory: Array.isArray(w.workerCountHistory) ? [...w.workerCountHistory] : []
          };

          if (!updated.completionHistoryReplacements.includes(key)) updated.completionHistoryReplacements.push(key);

          if (directTarget > 0) {
            updated.dailyCompleted[key] = directTarget;
            updated.dailyCompletedDeletions = updated.dailyCompletedDeletions.filter(x => String(x) !== key);
            updated.completionHistory.push({
              id: 'wch-worker-' + crypto.randomBytes(8).toString('hex'),
              workId: w.id,
              employeeId,
              date,
              workName: w.title || w.workName || job.partName,
              pieces: directTarget,
              cumulativeCompleted: directTarget,
              recordedAt: Date.now()
            });
          } else {
            delete updated.dailyCompleted[key];
            if (!updated.dailyCompletedDeletions.includes(key)) updated.dailyCompletedDeletions.push(key);
          }

          updated.workerCountHistory.push({
            id: 'worker-count-' + crypto.randomBytes(8).toString('hex'),
            requestId: requestId || null,
            employeeId,
            date,
            fromCount: workCompletedForDateServer(w, date, employeeId),
            finalCount,
            updatedAt: Date.now()
          });

          return updated;
        })
      };

      const merged = mergeEntityRecord('fl_workorders', job, updatedJob);
      validateWorkOrderRecords([merged]);
      validateWorkOrderCounts([merged]);
      const writeResult = await writeEntityRecords('fl_workorders', [merged]);
      // writeEntityRecords resolves only after Previous/Pending JSON has been
      // written and read-back verified. Also verify the exact requested count
      // in the resulting in-memory/current record before returning success.
      // Reload through the same authoritative CSV + current JSON + Previous/Pending
      // overlay used by subsequent API reads. Verify the exact work, employee and
      // date as well as the count represented by the application's count model.
      const persistedJob = Array.isArray(writeResult?.committedRecords) ? writeResult.committedRecords.find(x => recordId(x) === jobId) : null;
      const persistedWork = persistedJob?.works?.find(x => recordId(x) === workId);
      const persistedDaily = Number((persistedWork?.dailyCompleted || {})[key] || 0);
      const persistedHistory = (persistedWork?.workerCountHistory || []).some(x =>
        requestId && String(x?.requestId || '') === requestId && String(x?.employeeId || '') === employeeId && String(x?.date || '') === date && Number(x?.finalCount) === finalCount
      );
      const dailyMatches = directTarget > 0
        ? persistedDaily === directTarget
        : persistedDaily === 0 && (persistedWork?.dailyCompletedDeletions || []).includes(key);
      const effectiveCountMatches = !!persistedWork && workCompletedForDateServer(persistedWork, date, employeeId) === finalCount;
      const workStillAssigned = !!persistedWork && assignedIdsServer(persistedWork).includes(employeeId);
      if (!persistedJob || persistedJob.isDeleted === true || !persistedWork || !workStillAssigned || !dailyMatches || !effectiveCountMatches || (requestId && !persistedHistory)) {
        throw new Error('Worker count was not verified in the saved Work Order. Please retry after reloading My Work.');
      }
      return {writeResult, job:reconcileWorkOrderDerivedFields(persistedJob), finalCount, date, employeeId, verified:true};
    });

    return res.json({ok:true,...result});
  } catch (error) {
    console.error('Worker work count update failed:', error.message);
    return res.status(error.statusCode || 500).json({ok:false,error:error.message || 'Worker work count update failed.'});
  }
});

function workEmployeeActivityDatesServer(work, employeeId) {
  const eid = String(employeeId || '').trim();
  const dates = new Set();
  if (!eid) return dates;
  Object.entries(work?.dailyCompleted || {}).forEach(([key, value]) => {
    const skey = String(key);
    if (!skey.endsWith(':' + eid)) return;
    const date = skey.slice(0, 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(date) && Number.isFinite(Number(value)) && Number(value) >= 0) dates.add(date);
  });
  Object.entries(work?.workDayRecords || {}).forEach(([key, value]) => {
    const skey = String(key);
    if (!skey.endsWith(':' + eid) || value?.worked !== true) return;
    const date = skey.slice(0, 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) dates.add(date);
  });
  (Array.isArray(work?.completionHistory) ? work.completionHistory : []).forEach(item => {
    if (String(item?.employeeId || '') !== eid) return;
    const date = String(item?.date || '');
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) dates.add(date);
  });
  (Array.isArray(work?.adminCountAdjustments) ? work.adminCountAdjustments : []).forEach(item => {
    if (String(item?.employeeId || '') !== eid) return;
    const date = String(item?.date || '');
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) dates.add(date);
  });
  return dates;
}

function isValidAdminCountActivityDateServer(work, date, employeeId) {
  const value = String(date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  if (value > appTodayStr()) return false;
  return workEmployeeActivityDatesServer(work, employeeId).has(value);
}

/* ---------------------------------------------------------
 * Admin batch work-count update
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/admin-count', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  const workId = safeString(req.body?.workId).trim();
  const employeeId = safeString(req.body?.employeeId).trim();
  const date = safeString(req.body?.date).trim();
  const finalCount = Number(req.body?.finalCount);
  const requestId = safeString(req.body?.requestId).trim();
  if (!jobId || !workId || !employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(finalCount) || !Number.isInteger(finalCount)) {
    return res.status(400).json({ ok:false, error:'Job, Work, Employee, valid activity date and final count are required.' });
  }
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || job.isDeleted === true) throw Object.assign(new Error('Work Order not found.'), { statusCode:404 });
      const employee = (await getEmployeesFromStore(true)).find(x => !isDeleted(x) && employeeIdOf(x) === employeeId);
      if (!employee || !['WORKER','ADMIN_WORKER'].includes(employeeRoleOf(employee))) throw Object.assign(new Error('Select a valid Worker or Admin & Worker employee.'), { statusCode:400 });
      const work = Array.isArray(job.works) ? job.works.find(x => recordId(x) === workId) : null;
      if (!work || String(work.workType || 'PIECE').toUpperCase() !== 'PIECE') throw Object.assign(new Error('Admin count controls apply only to Pieces Based work.'), { statusCode:400 });
      const assignedEmployeeIds = new Set(assignedIdsServer(work).map(String));
      if (!assignedEmployeeIds.has(employeeId)) throw Object.assign(new Error('The selected employee is not assigned to this Work.'), { statusCode:400 });
      if (!isValidAdminCountActivityDateServer(work, date, employeeId)) throw Object.assign(new Error('The selected date has no valid saved activity for this employee and Work.'), { statusCode:400 });
      const total = workTotalRequired(job, work);
      if (!Number.isFinite(total) || total <= 0) throw Object.assign(new Error('Work Total Pieces Required is missing.'), { statusCode:400 });
      const normalizedJob = reconcileWorkOrderDerivedFields(job);
      const normalizedWork = normalizedJob.works.find(x => recordId(x) === workId);
      if (requestId && Array.isArray(normalizedWork?.adminCountAdjustments)) {
        const existingRequest = normalizedWork.adminCountAdjustments.find(x => String(x?.requestId || '') === requestId);
        if (existingRequest) {
          const sameRequest = String(existingRequest.employeeId || '') === employeeId && String(existingRequest.date || '') === date &&
            (existingRequest.requestedFinalCount == null || Number(existingRequest.requestedFinalCount) === finalCount) &&
            (req.body?.changeDelta == null || Number(existingRequest.delta) === Number(req.body.changeDelta));
          if (!sameRequest) throw Object.assign(new Error('This count request ID was already used for a different worker, date, or quantity.'), {statusCode:409});
          return { writeResult: { duplicate:true }, job: normalizedJob, employeeId, date, finalCount: Number(existingRequest.finalCount ?? 0), globalFinalCount: Number(normalizedWork.completed||0), verified:true, duplicate:true };
        }
      }
      const currentGlobal = Math.max(0, Math.min(total, Number(normalizedWork?.completed || 0)));
      const requestedDelta = Number(req.body?.changeDelta);
      const delta = Number.isFinite(requestedDelta) && Number.isInteger(requestedDelta)
        ? Math.trunc(requestedDelta)
        : Math.trunc(finalCount) - currentGlobal;
      const employeeCurrent = workCompletedForDateServer(normalizedWork, date, employeeId);
      const employeeTarget = employeeCurrent + delta;
      const globalTarget = currentGlobal + delta;
      if (employeeTarget < 0) throw Object.assign(new Error(`Completed quantity for the selected employee cannot be negative. Current count is ${employeeCurrent}.`), { statusCode:400 });
      if (employeeTarget > total) throw Object.assign(new Error(`Completed quantity for the selected employee cannot exceed this Work's Total Pieces Required (${total}).`), { statusCode:400 });
      if (globalTarget < 0) throw Object.assign(new Error('Completed quantity cannot be negative.'), { statusCode:400 });
      if (globalTarget > total) {
        const remaining = Math.max(0, total - currentGlobal);
        throw Object.assign(new Error(`Completed quantity cannot exceed this Work's remaining quantity (${remaining}).`), { statusCode:400 });
      }
      const target = employeeTarget;
      const updatedAt = new Date(Math.max(Date.now(), recordSyncTimestamp(job) + 1)).toISOString();
      const updatedJob = { ...job, updatedAt, updated_at:updatedAt, works: Array.isArray(job.works) ? job.works.map(w => {
        if (recordId(w) !== workId) return w;
        const adjustments = adminAdjustmentsForWork(w);
        adjustments.push({
          id: 'admin-count-' + crypto.randomBytes(8).toString('hex'),
          date,
          employeeId,
          requestId: requestId || null,
          delta,
          fromCount: employeeCurrent,
          finalCount: target,
          requestedFinalCount: finalCount,
          createdAt: Date.now()
        });
        const updated = { ...w, adminCountAdjustments: adjustments };
        delete updated.adminCompletedOverride;
        return updated;
      }) : [] };
      const merged = mergeEntityRecord('fl_workorders', job, updatedJob);
      validateWorkOrderRecords([merged]);
      validateWorkOrderCounts([merged]);
      const writeResult = await writeEntityRecords('fl_workorders', [merged]);
      // Confirm the specific adjustment exists in the record returned by the
      // authoritative current/pending state after durable persistence.
      const persistedJob = Array.isArray(writeResult?.committedRecords) ? writeResult.committedRecords.find(x => recordId(x) === jobId) : null;
      const persistedWork = persistedJob?.works?.find(x => recordId(x) === workId);
      const persistedAdjustment = (persistedWork?.adminCountAdjustments || []).find(x =>
        requestId && String(x?.requestId || '') === requestId && String(x?.employeeId || '') === employeeId && String(x?.date || '') === date
      );
      if (!persistedJob || !persistedWork || (requestId && (!persistedAdjustment || Number(persistedAdjustment.delta) !== delta || Number(persistedAdjustment.finalCount) !== target))) {
        throw new Error('Admin count update was not verified in the saved Work Order. Please reload and retry.');
      }
      return { writeResult: { count:writeResult.count, activeCount:writeResult.activeCount }, job: reconcileWorkOrderDerivedFields(persistedJob), employeeId, date, finalCount: target, globalFinalCount: globalTarget, verified:true };
    });
    return res.json({ ok:true, ...result });
  } catch (error) {
    console.error('Admin work count update failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Admin count update failed.' });
  }
});

function employeeCompletedForWorkServer(work, employeeId){
  const eid=String(employeeId||'').trim();
  if(!eid) return 0;
  const daily=Object.entries(work?.dailyCompleted||{})
    .filter(([key])=>String(key).endsWith(':'+eid))
    .reduce((sum,[,value])=>sum+Math.max(0,Number(value||0)),0);
  const history=(Array.isArray(work?.completionHistory)?work.completionHistory:[])
    .filter(item=>String(item?.employeeId||'')===eid)
    .reduce((sum,item)=>sum+Math.max(0,Number(item?.pieces||0)),0);
  const adjustments=adminAdjustmentsForWork(work)
    .filter(item=>String(item?.employeeId||'')===eid)
    .reduce((sum,item)=>sum+Number(item?.delta||0),0);
  return Math.max(0, (daily>0?daily:history) + adjustments);
}

function adminCountAdjustmentForDateServer(work,date,employeeId){
  return (Array.isArray(work?.adminCountAdjustments)?work.adminCountAdjustments:[])
    .filter(x=>String(x?.date||'')===String(date)&&String(x?.employeeId||'')===String(employeeId))
    .reduce((s,x)=>s+Number(x?.delta||0),0);
}
function workCompletedForDateServer(work,date,employeeId){
  const key=`${date}:${employeeId}`;
  const direct=Number((work?.dailyCompleted||{})[key]||0);
  const history=(work?.completionHistory||[]).filter(x=>String(x?.date)===String(date)&&String(x?.employeeId)===String(employeeId)).reduce((s,x)=>s+Number(x?.pieces||0),0);
  return Math.max(0,direct||history)+adminCountAdjustmentForDateServer(work,date,employeeId);
}

/* ---------------------------------------------------------
 * Admin correction of an existing worker/date completed count
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/correct-count', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  const workId = safeString(req.body?.workId).trim();
  const employeeId = safeString(req.body?.employeeId).trim();
  const date = safeString(req.body?.date).trim();
  const finalCount = Number(req.body?.finalCount);
  const requestId = safeString(req.body?.requestId).trim();
  if (!jobId || !workId || !employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(finalCount) || !Number.isInteger(finalCount) || finalCount < 0) {
    return res.status(400).json({ ok:false, error:'Job, Work, Worker, valid date and non-negative whole count are required.' });
  }
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || job.isDeleted === true) throw Object.assign(new Error('Work Order not found.'), { statusCode:404 });
      const employee = (await getEmployeesFromStore(true)).find(x => !isDeleted(x) && employeeIdOf(x) === employeeId);
      if (!employee || !['WORKER','ADMIN_WORKER'].includes(employeeRoleOf(employee))) throw Object.assign(new Error('Select a valid Worker or Admin & Worker employee.'), { statusCode:400 });
      const work = Array.isArray(job.works) ? job.works.find(x => recordId(x) === workId) : null;
      if (!work || String(work.workType || 'PIECE').toUpperCase() !== 'PIECE') throw Object.assign(new Error('Count correction applies only to Pieces Based work.'), { statusCode:400 });
      if (!Array.isArray(work.assignedTo) || !work.assignedTo.map(String).includes(employeeId)) throw Object.assign(new Error('The selected worker is not assigned to this Work.'), { statusCode:400 });
      const total = workTotalRequired(job, work);
      if (!Number.isFinite(total) || total <= 0) throw Object.assign(new Error('Work Total Pieces Required is missing.'), { statusCode:400 });
      const key = `${date}:${employeeId}`;
      const adjustment = adminCountAdjustmentForDateServer(work, date, employeeId);
      const directTarget = finalCount - adjustment;
      if (directTarget < 0) throw Object.assign(new Error('Corrected count conflicts with an existing admin adjustment for this worker/date.'), { statusCode:400 });
      const dailyEntries = Object.entries(work.dailyCompleted || {});
      const hasDailyEntries = dailyEntries.length > 0;
      const otherDailyTotal = dailyEntries.filter(([k])=>k!==key).reduce((sum,[,v])=>sum+Math.max(0,Number(v||0)),0);
      const otherHistoryTotal = hasDailyEntries ? 0 : (Array.isArray(work.completionHistory)?work.completionHistory.filter(x=>`${x?.date}:${x?.employeeId}`!==key).reduce((sum,x)=>sum+Math.max(0,Number(x?.pieces||0)),0):0);
      const adminDelta = adminAdjustmentsForWork(work).reduce((sum,item)=>sum+Number(item?.delta||0),0);
      const resultingTotal = otherDailyTotal + otherHistoryTotal + directTarget + adminDelta;
      if (resultingTotal > total) throw Object.assign(new Error(`Corrected count would exceed the Work Total Pieces Required (${total}).`), { statusCode:400 });
      if (requestId) {
        const prior = Array.isArray(work.correctionHistory) && work.correctionHistory.find(x => String(x?.requestId || '') === requestId);
        if (prior) {
          if (String(prior.employeeId || '') !== employeeId || String(prior.date || '') !== date || Number(prior.finalCount) !== finalCount) {
            throw Object.assign(new Error('This correction request ID was already used for a different employee, date, or count. Reload the Work Order and submit the changed correction with a new request.'), { statusCode:409 });
          }
          const priorCount = workCompletedForDateServer(work, date, employeeId);
          if (Number(priorCount) !== Number(prior.finalCount)) throw Object.assign(new Error('The previous correction request exists, but its stored count does not match. Reload saved Work Orders before retrying.'), { statusCode:409 });
          return { job: reconcileWorkOrderDerivedFields(job), duplicate:true, finalCount:Number(prior.finalCount), employeeId, date, verified:true };
        }
      }
      // Stamp this correction newer than the loaded Work Order before writing.
      // Pending JSON reconciliation is timestamp-aware; without a fresh updatedAt,
      // an older count snapshot with a later timestamp can win the merge and make
      // the immediate read-back appear to lose the saved correction (HTTP 503).
      const correctionUpdatedAt = new Date(Math.max(Date.now(), recordSyncTimestamp(job) + 1)).toISOString();
      const updatedJob = { ...job, updatedAt:correctionUpdatedAt, updated_at:correctionUpdatedAt, works: job.works.map(w => {
        if (recordId(w) !== workId) return w;
        const updated = { ...w, dailyCompleted:{...(w.dailyCompleted||{})}, completionHistory:Array.isArray(w.completionHistory)?w.completionHistory.filter(x => !(String(x?.date)===date && String(x?.employeeId)===employeeId)):[], completionHistoryReplacements:[...(w.completionHistoryReplacements||[]), key], correctionHistory:[...(w.correctionHistory||[])] };
        updated.dailyCompletedDeletions = Array.isArray(updated.dailyCompletedDeletions) ? updated.dailyCompletedDeletions : [];
        if (directTarget > 0) {
          updated.dailyCompleted[key] = directTarget;
          updated.dailyCompletedDeletions = updated.dailyCompletedDeletions.filter(x=>String(x)!==key);
        } else {
          delete updated.dailyCompleted[key];
          if (!updated.dailyCompletedDeletions.includes(key)) updated.dailyCompletedDeletions.push(key);
        }
        if (directTarget > 0) {
          updated.completionHistory.push({ id:'wch-correction-' + crypto.randomBytes(8).toString('hex'), workId:w.id, employeeId, date, workName:w.title||w.workName||job.partName, pieces:directTarget, cumulativeCompleted:directTarget, corrected:true, recordedAt:Date.now() });
        }
        updated.correctionHistory.push({ id:'correction-' + crypto.randomBytes(8).toString('hex'), requestId:requestId||null, employeeId, date, fromCount:workCompletedForDateServer(w,date,employeeId), finalCount, correctedAt:Date.now() });
        return updated;
      }) };
      const merged = mergeEntityRecord('fl_workorders', job, updatedJob);
      validateWorkOrderRecords([merged]);
      validateWorkOrderCounts([merged]);
      const writeResult = await writeEntityRecords('fl_workorders', [merged]);
      // writeEntityRecords resolves only after the durable Previous/Pending
      // snapshot and the affected encrypted JSON partitions have been persisted
      // and their configured GitHub mirror writes have completed. Its returned
      // record is the committed version. Do not trigger another full entity load
      // and merge after the commit: stale overlay reconciliation was the source
      // of false 503 responses for otherwise committed historical corrections.
      const persistedJob = Array.isArray(writeResult?.records)
        ? writeResult.records.find(x => recordId(x) === jobId)
        : null;
      const persistedWork = Array.isArray(persistedJob?.works)
        ? persistedJob.works.find(x => recordId(x) === workId)
        : null;
      const persistedCount = persistedWork ? workCompletedForDateServer(persistedWork, date, employeeId) : null;
      const persistedCorrection = Array.isArray(persistedWork?.correctionHistory) && persistedWork.correctionHistory.some(x => String(x?.requestId || '') === requestId && String(x?.employeeId || '') === employeeId && String(x?.date || '') === date && Number(x?.finalCount) === finalCount);
      if (!persistedJob || persistedJob.isDeleted === true || !persistedWork || !Array.isArray(persistedWork.assignedTo) || !persistedWork.assignedTo.map(String).includes(employeeId) || Number(persistedCount) !== finalCount || (requestId && !persistedCorrection)) {
        console.error('Committed Work Order count did not match the requested correction', JSON.stringify({ jobId, workId, employeeId, date, finalCount, persistedCount, requestId, writeResultCount: Array.isArray(writeResult?.records) ? writeResult.records.length : null }));
        throw Object.assign(new Error('The durable write completed but the committed Work Order did not contain the requested count. The change has been retained for recovery; reload the record before retrying.'), { statusCode: 500 });
      }
      return { writeResult: { count: writeResult.count, activeCount: writeResult.activeCount }, job:reconcileWorkOrderDerivedFields(persistedJob), employeeId, date, finalCount, verified:true };
    });
    return res.json({ ok:true, ...result });
  } catch (error) {
    const detail = safeString(error?.message || 'Work count correction failed.');
    const transientPersistenceFailure = /github|persist|operational json|previous\/pending|timed? ?out|eai_again|enotfound|econnreset|fetch failed|network/i.test(detail);
    const statusCode = Number(error?.statusCode) || (transientPersistenceFailure ? 503 : 500);
    console.error('Admin work count correction failed', JSON.stringify({ jobId, workId, employeeId, date, finalCount, requestId, statusCode, error:detail, stack:error?.stack || null }));
    return res.status(statusCode).json({ ok:false, error:detail || 'Work count correction failed.', retryable:statusCode === 503 });
  }
});

/* ---------------------------------------------------------
 * Admin correction of an existing non-piece worker/date record
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/correct-daily', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  const workId = safeString(req.body?.workId).trim();
  const employeeId = safeString(req.body?.employeeId).trim();
  const date = safeString(req.body?.date).trim();
  const type = safeString(req.body?.type).trim().toUpperCase();
  const requestId = safeString(req.body?.requestId).trim();
  if (!jobId || !workId || !employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !['NO_FIXED','WORK_BASED'].includes(type)) {
    return res.status(400).json({ ok:false, error:'Job, Work, Worker, valid date and valid non-piece Work Type are required.' });
  }
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || job.isDeleted === true) throw Object.assign(new Error('Work Order not found.'), { statusCode:404 });
      const employee = (await getEmployeesFromStore(true)).find(x => !isDeleted(x) && employeeIdOf(x) === employeeId);
      if (!employee || !['WORKER','ADMIN_WORKER'].includes(employeeRoleOf(employee))) throw Object.assign(new Error('Select a valid Worker or Admin & Worker employee.'), { statusCode:400 });
      const work = Array.isArray(job.works) ? job.works.find(x => recordId(x) === workId) : null;
      if (!work || normalizeWorkTypeServer(work.workType) !== type) throw Object.assign(new Error('Selected Work Type does not match the requested correction.'), { statusCode:400 });
      if (!Array.isArray(work.assignedTo) || !work.assignedTo.map(String).includes(employeeId)) throw Object.assign(new Error('The selected worker is not assigned to this Work.'), { statusCode:400 });
      const key = `${date}:${employeeId}`;
      if (requestId && Array.isArray(work.correctionHistory) && work.correctionHistory.some(x => String(x?.requestId || '') === requestId)) {
        const prior=work.correctionHistory.find(x => String(x?.requestId || '') === requestId);
        return { duplicate:true, job:reconcileWorkOrderDerivedFields(job), employeeId, date, verified:true, correction:prior };
      }
      const dailyCorrectionUpdatedAt = new Date(Math.max(Date.now(), recordSyncTimestamp(job) + 1)).toISOString();
      const updatedJob = { ...job, updatedAt:dailyCorrectionUpdatedAt, updated_at:dailyCorrectionUpdatedAt, works: job.works.map(w => {
        if (recordId(w) !== workId) return w;
        const updated = { ...w, correctionHistory:[...(w.correctionHistory||[])], completionHistoryReplacements:[...(w.completionHistoryReplacements||[]), key] };
        if (type === 'NO_FIXED') {
          const worked = req.body?.worked === true || String(req.body?.worked).toLowerCase() === 'true';
          const finalCount = worked ? Number(req.body?.finalCount) : 0;
          if (worked && (!Number.isFinite(finalCount) || !Number.isInteger(finalCount) || finalCount < 0)) throw Object.assign(new Error('Completed count must be a non-negative whole number.'), { statusCode:400 });
          updated.dailyCompleted = { ...(updated.dailyCompleted || {}) };
          updated.dailyCompletedDeletions = Array.isArray(updated.dailyCompletedDeletions) ? [...updated.dailyCompletedDeletions] : [];
          updated.workDayRecords = { ...(updated.workDayRecords || {}) };
          updated.workDayRecordDeletions = Array.isArray(updated.workDayRecordDeletions) ? [...updated.workDayRecordDeletions] : [];
          updated.notWorkedRecords = Array.isArray(updated.notWorkedRecords) ? [...updated.notWorkedRecords] : [];
          updated.notWorkedRecordDeletions = Array.isArray(updated.notWorkedRecordDeletions) ? [...updated.notWorkedRecordDeletions] : [];
          updated.completionHistory = Array.isArray(updated.completionHistory) ? updated.completionHistory.filter(x => !(String(x?.date)===date && String(x?.employeeId)===employeeId)) : [];
          updated.completionHistoryReplacements = Array.isArray(updated.completionHistoryReplacements) ? [...updated.completionHistoryReplacements, key] : [key];
          updated.notWorkedRecords = updated.notWorkedRecords.filter(x=>!(String(x?.date)===date&&String(x?.employeeId)===employeeId));
          delete updated.workDayRecords[key];
          if (!worked) {
            delete updated.dailyCompleted[key];
            if (!updated.dailyCompletedDeletions.includes(key)) updated.dailyCompletedDeletions.push(key);
            if (!updated.workDayRecordDeletions.includes(key)) updated.workDayRecordDeletions.push(key);
            updated.notWorkedRecords.push({employeeId,date,updatedAt:Date.now(),corrected:true});
          } else {
            // Persist the fact that the employee worked independently of the
            // optional count. A valid zero count must still appear in Work Status.
            updated.workDayRecords[key] = { worked:true, hours:0, employeeId, date, count:finalCount, updatedAt:Date.now(), corrected:true };
            updated.workDayRecordDeletions = updated.workDayRecordDeletions.filter(x=>String(x)!==key);
            if (!updated.notWorkedRecordDeletions.includes(key)) updated.notWorkedRecordDeletions.push(key);
            if (finalCount > 0) {
              updated.dailyCompleted[key] = finalCount;
              updated.dailyCompletedDeletions = updated.dailyCompletedDeletions.filter(x=>String(x)!==key);
              updated.completionHistory.push({ id:'wch-daily-correction-' + crypto.randomBytes(8).toString('hex'), workId:w.id, employeeId, date, workName:w.title||w.workName||job.partName, pieces:finalCount, corrected:true, recordedAt:Date.now() });
            } else {
              delete updated.dailyCompleted[key];
              if (!updated.dailyCompletedDeletions.includes(key)) updated.dailyCompletedDeletions.push(key);
            }
          }
          updated.correctionHistory.push({ id:'daily-correction-' + crypto.randomBytes(8).toString('hex'), requestId:requestId||null, type, employeeId, date, worked, finalCount, correctedAt:Date.now() });
        } else {
          const worked = req.body?.worked === true || String(req.body?.worked).toLowerCase() === 'true';
          const hours = worked ? Number(req.body?.hours) : 0;
          if (worked && (!Number.isFinite(hours) || hours <= 0)) throw Object.assign(new Error('Time/hours must be greater than zero for Worked status.'), { statusCode:400 });
          if (!Number.isFinite(hours) || hours < 0) throw Object.assign(new Error('Time/hours must be a valid non-negative number.'), { statusCode:400 });
          updated.workDayRecords = { ...(updated.workDayRecords || {}) };
          updated.workDayRecordDeletions = Array.isArray(updated.workDayRecordDeletions) ? [...updated.workDayRecordDeletions] : [];
          updated.notWorkedRecords = Array.isArray(updated.notWorkedRecords) ? updated.notWorkedRecords.filter(x=>!(String(x?.date)===date&&String(x?.employeeId)===employeeId)) : [];
          updated.notWorkedRecordDeletions = Array.isArray(updated.notWorkedRecordDeletions) ? [...updated.notWorkedRecordDeletions] : [];
          delete updated.workDayRecords[key];
          if (worked && hours>0) {
            updated.workDayRecords[key] = { worked:true, hours, employeeId, date, updatedAt:Date.now(), corrected:true };
            updated.workDayRecordDeletions = updated.workDayRecordDeletions.filter(x=>String(x)!==key);
            if (!updated.notWorkedRecordDeletions.includes(key)) updated.notWorkedRecordDeletions.push(key);
          } else if (!worked) {
            if (!updated.workDayRecordDeletions.includes(key)) updated.workDayRecordDeletions.push(key);
            updated.notWorkedRecords.push({employeeId,date,updatedAt:Date.now(),corrected:true});
          } else if (!updated.workDayRecordDeletions.includes(key)) {
            updated.workDayRecordDeletions.push(key);
          }
          updated.correctionHistory.push({ id:'daily-correction-' + crypto.randomBytes(8).toString('hex'), requestId:requestId||null, type, employeeId, date, worked, hours, correctedAt:Date.now() });
        }
        return updated;
      }) };
      const merged = mergeEntityRecord('fl_workorders', job, updatedJob);
      validateWorkOrderRecords([merged]);
      const writeResult = await writeEntityRecords('fl_workorders', [merged]);
      const persistedRows = loadEntityAll('fl_workorders');
      const persistedJob = persistedRows.find(x => recordId(x) === jobId);
      const persistedWork = Array.isArray(persistedJob?.works) ? persistedJob.works.find(x => recordId(x) === workId) : null;
      const persistedKey = `${date}:${employeeId}`;
      const persistedHistory = Array.isArray(persistedWork?.correctionHistory) ? persistedWork.correctionHistory.find(x => String(x?.requestId || '') === requestId && String(x?.employeeId || '') === employeeId && String(x?.date || '') === date) : null;
      let verified = false;
      if (type === 'NO_FIXED') {
        const savedCount = Number((persistedWork?.dailyCompleted || {})[persistedKey] || 0);
        const savedWorked = (persistedWork?.workDayRecords || {})[persistedKey]?.worked === true;
        verified = req.body?.worked === true || String(req.body?.worked).toLowerCase() === 'true'
          ? savedWorked && savedCount === Number(req.body?.finalCount || 0)
          : !Object.prototype.hasOwnProperty.call(persistedWork?.dailyCompleted || {}, persistedKey) && !Object.prototype.hasOwnProperty.call(persistedWork?.workDayRecords || {}, persistedKey);
      } else {
        const expectedWorked = req.body?.worked === true || String(req.body?.worked).toLowerCase() === 'true';
        const savedRecord = (persistedWork?.workDayRecords || {})[persistedKey];
        const savedWorked = savedRecord?.worked === true;
        const savedHours = Number(savedRecord?.hours || 0);
        verified = expectedWorked ? savedWorked && savedHours === Number(req.body?.hours) : !savedRecord;
      }
      if (!persistedJob || persistedJob.isDeleted === true || !persistedWork || !persistedHistory || !verified) {
        throw Object.assign(new Error('Daily work record was written but could not be verified from the reloaded saved Work Order. Your entered values are retained for retry; check the saved record before retrying.'), { statusCode:503 });
      }
      return { writeResult, job:reconcileWorkOrderDerivedFields(persistedJob), employeeId, date, verified:true };
    });
    return res.json({ ok:true, ...result });
  } catch (error) {
    console.error('Admin daily work correction failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Daily work correction failed.' });
  }
});

/* ---------------------------------------------------------
 * Work assignment update with backend validation
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/assign', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  const workId = safeString(req.body?.workId).trim();
  const employeeIds = Array.isArray(req.body?.employeeIds) ? [...new Set(req.body.employeeIds.map(x => safeString(x).trim()).filter(Boolean))] : [];
  if (!jobId || !workId) return res.status(400).json({ ok:false, error:'Job and Work are required.' });
  if (!employeeIds.length) return res.status(400).json({ ok:false, error:'Please select a worker before saving the assignment.' });
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || job.isDeleted === true) throw Object.assign(new Error('Work Order not found.'), { statusCode:404 });
      const work = Array.isArray(job.works) ? job.works.find(x => recordId(x) === workId) : null;
      if (!work) throw Object.assign(new Error('Work not found.'), { statusCode:404 });
      const employees = await getEmployeesFromStore(true);
      const activeIds = new Set(employees.filter(x => employeeActiveOnDateServer(x) && ['WORKER','ADMIN_WORKER'].includes(employeeRoleOf(x))).map(employeeIdOf));
      const invalid = employeeIds.filter(id => !activeIds.has(id));
      if (invalid.length) throw Object.assign(new Error('Please select only eligible Worker or Admin & Worker employees.'), { statusCode:400 });
      // Assignment is a durable Work Order change. Give this exact save a
      // fresh timestamp so the date-independent Previous/Pending buffer and
      // all later reloads cannot prefer an older Work Order snapshot that does
      // not contain the newly selected employees.
      const updated = {
        ...job,
        updatedAt: new Date().toISOString(),
        works: job.works.map(w =>
          recordId(w) === workId
            ? { ...w, assignedTo: employeeIds }
            : w
        )
      };
      const merged = mergeEntityRecord('fl_workorders', job, updated);
      validateWorkOrderRecords([merged]);
      const writeResult = await writeEntityRecords('fl_workorders', [merged]);
      return { writeResult, job: reconcileWorkOrderDerivedFields(merged) };
    });
    return res.json({ ok:true, ...result });
  } catch (error) {
    console.error('Work assignment update failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Assignment update failed.' });
  }
});

/* ---------------------------------------------------------
 * Restore a deleted, incomplete Work Order from its preserved
 * active-record tombstone and historical snapshot. Keep the same
 * Job ID and nested Work IDs; do not recreate historical records.
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/restore', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  if (!jobId) return res.status(400).json({ ok:false, error:'Work Order ID is required.' });
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const latestOrders = loadEntityAll('fl_workorders');
      const deletedOrder = latestOrders.find(record => recordId(record) === jobId);
      if (!deletedOrder || !isDeleted(deletedOrder)) {
        throw Object.assign(new Error('Deleted Work Order was not found.'), { statusCode:404 });
      }
      const historyRecords = loadEntityAll('fl_workhistory');
      const history = historyRecords.find(record => recordId(record) === jobId && !isDeleted(record));
      if (!history) {
        throw Object.assign(new Error('The original Work Order history is unavailable; it cannot be restored safely.'), { statusCode:409 });
      }
      if (history.permanentDeletePending === true) {
        throw Object.assign(new Error('Permanent deletion is pending. Retry Permanent Delete to finish cleanup before restoring this Work Order.'), { statusCode:409 });
      }
      const reason = safeString(history.archivedReason || deletedOrder.archivedReason).trim().toLowerCase();
      const status = safeString(history.status || deletedOrder.status).trim().toUpperCase();
      if (reason !== 'deleted' || status === 'DONE' || reason === 'done') {
        throw Object.assign(new Error('Only Work Orders deleted before completion can be restored.'), { statusCode:409 });
      }
      // A deleted inward/PO job may have been reused after deletion. Never
      // restore a second active Work Order against the same source item.
      const linkedDuplicate = latestOrders.find(candidate => {
        if (!candidate || recordId(candidate) === jobId || isDeleted(candidate) || candidate.archived === true) return false;
        const sameInward = safeString(deletedOrder.inwardId).trim() && safeString(deletedOrder.inwardItemId).trim()
          && safeString(candidate.inwardId).trim() === safeString(deletedOrder.inwardId).trim()
          && safeString(candidate.inwardItemId).trim() === safeString(deletedOrder.inwardItemId).trim();
        const samePurchaseOrder = safeString(deletedOrder.purchaseOrderId).trim() && safeString(deletedOrder.purchaseOrderItemId).trim()
          && safeString(candidate.purchaseOrderId).trim() === safeString(deletedOrder.purchaseOrderId).trim()
          && safeString(candidate.purchaseOrderItemId).trim() === safeString(deletedOrder.purchaseOrderItemId).trim();
        return Boolean(sameInward || samePurchaseOrder);
      });
      if (linkedDuplicate) {
        throw Object.assign(new Error('This Inwards or Purchase Order item is already assigned to another active Work Order. Resolve that assignment before restoring this deleted job.'), { statusCode:409 });
      }
      const source = mergeEntityRecord('fl_workorders', history, deletedOrder);
      if (workOrderCompletedForRestore(source)) {
        throw Object.assign(new Error('This Work Order was already completed and cannot be restored through incomplete-job recovery.'), { statusCode:409 });
      }
      const restored = reconcileWorkOrderDerivedFields({
        ...source,
        id: jobId,
        isDeleted: false,
        archived: false,
        active: true,
        status: 'ACTIVE',
        updatedAt: new Date().toISOString()
      });
      delete restored.archivedAt;
      delete restored.archivedReason;
      delete restored.completionDate;
      validateWorkOrderRecords([restored]);
      const writeResult = await writeEntityRecords('fl_workorders', [restored]);
      const saved = loadEntityAll('fl_workorders').find(record => recordId(record) === jobId);
      const expectedWorkIds = (Array.isArray(restored.works) ? restored.works : []).map(recordId).filter(Boolean).sort();
      const savedWorkIds = (Array.isArray(saved?.works) ? saved.works : []).map(recordId).filter(Boolean).sort();
      if (!saved || isDeleted(saved) || saved.archived === true || expectedWorkIds.length !== savedWorkIds.length || expectedWorkIds.some((id,index) => id !== savedWorkIds[index])) {
        throw Object.assign(new Error('Restored Work Order could not be verified in saved state. Refresh and retry.'), { statusCode:500 });
      }
      return { job: reconcileWorkOrderDerivedFields(saved), writeResult, verified:true };
    });
    return res.json({ ok:true, ...result });
  } catch (error) {
    console.error('Work Order restore failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Could not restore Work Order.' });
  }
});

/* ---------------------------------------------------------
 * Permanently delete an already-deleted Work Order.
 * Keep a minimal tombstone because the existing CSV/JSON storage layer
 * intentionally merges records by stable ID instead of physically removing
 * rows. Scrub the nested Works so daily counts, assignments and completion
 * history cannot be restored or leak into active views.
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/permanent-delete', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  if (!jobId) return res.status(400).json({ ok:false, error:'Work Order ID is required.' });
  if (req.body?.confirmed !== true) return res.status(400).json({ ok:false, error:'Explicit confirmation is required for permanent deletion.' });
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const deletedOrder = loadEntityRecordById('fl_workorders', jobId);
      const history = loadEntityRecordById('fl_workhistory', jobId);
      if (!deletedOrder || !isDeleted(deletedOrder)) {
        throw Object.assign(new Error('Only an already-deleted Work Order can be permanently deleted.'), { statusCode:409 });
      }
      if (!history) {
        throw Object.assign(new Error('The preserved Work Order history is unavailable; permanent deletion cannot be verified safely.'), { statusCode:409 });
      }
      const reason = safeString(history.archivedReason).trim().toLowerCase();
      if (!['deleted','permanently_deleted'].includes(reason)) {
        throw Object.assign(new Error('Only Work Orders in the Deleted Work Orders section can be permanently deleted.'), { statusCode:409 });
      }
      const stamp = new Date(Math.max(Date.now(), recordSyncTimestamp(history) + 1, recordSyncTimestamp(deletedOrder) + 1)).toISOString();
      const audit = {
        id: jobId,
        partName: safeString(history.partName || deletedOrder.partName || history.title || deletedOrder.title || 'Deleted Work Order'),
        date: safeString(history.date || deletedOrder.date).slice(0,10),
        createdAt: history.createdAt || deletedOrder.createdAt || null,
        deletedAt: history.deletedAt || deletedOrder.deletedAt || history.archivedAt || Date.now(),
        permanentlyDeletedAt: history.permanentlyDeletedAt || stamp,
        permanentlyDeleted: true,
        active: false,
        archived: true,
        status: 'ARCHIVED'
      };
      // First mark the preserved snapshot as pending, but keep its nested work
      // data intact. If any later write fails, the deleted row stays visible
      // with Restore disabled and Permanent Delete available for retry.
      const pendingHistory = { ...history, ...audit, updatedAt:stamp, isDeleted:false, archivedReason:'deleted', permanentDeletePending:true };
      await writeEntityRecords('fl_workhistory', [pendingHistory]);
      const orderStamp = new Date(Math.max(Date.now(), Date.parse(stamp) + 1)).toISOString();
      const tombstone = { ...audit, updatedAt:orderStamp, permanentDeletePending:false, isDeleted:true, archivedReason:'permanently_deleted', works:[] };
      const orderResult = await writeEntityRecords('fl_workorders', [{ ...deletedOrder, ...tombstone, __replaceWorks:true }]);
      // Ensure the final history tombstone is strictly newer than the pending
      // snapshot so timestamp-aware merges cannot resurrect the retry marker.
      const historyStamp = new Date(Math.max(Date.now(), Date.parse(orderStamp) + 1, recordSyncTimestamp(history) + 1)).toISOString();
      const historyResult = await writeEntityRecords('fl_workhistory', [{ ...history, ...tombstone, updatedAt:historyStamp }]);
      const savedHistory = (Array.isArray(historyResult?.committedRecords) ? historyResult.committedRecords : []).find(record => recordId(record) === jobId);
      const savedOrder = (Array.isArray(orderResult?.committedRecords) ? orderResult.committedRecords : []).find(record => recordId(record) === jobId);
      const verified = !!savedHistory && !!savedOrder && isDeleted(savedHistory) && isDeleted(savedOrder)
        && safeString(savedHistory.archivedReason).toLowerCase() === 'permanently_deleted'
        && safeString(savedOrder.archivedReason).toLowerCase() === 'permanently_deleted'
        && Array.isArray(savedHistory.works) && savedHistory.works.length === 0
        && Array.isArray(savedOrder.works) && savedOrder.works.length === 0;
      if (!verified) throw Object.assign(new Error('Permanent deletion was written but could not be verified in saved state. Retry the action to finish cleanup.'), { statusCode:500 });
      return { ok:true, verified:true, historyResult, orderResult, tombstone:savedHistory };
    });
    return res.json(result);
  } catch (error) {
    console.error('Permanent Work Order deletion failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Could not permanently delete Work Order.' });
  }
});

/* ---------------------------------------------------------
 * Archive active Work Order while preserving the latest
 * worker history from server-side state.
 * --------------------------------------------------------- */
app.post('/api/workorders/:jobId/archive', async (req, res) => {
  if (!requireAuth(req,res,['main_admin','admin_employee','admin_worker'])) return;
  const jobId = safeString(req.params.jobId).trim();
  if (!jobId) return res.status(400).json({ ok:false, error:'Work Order ID is required.' });
  try {
    const result = await withEntityWriteLock('fl_workorders', async () => {
      const job = loadEntityRecordById('fl_workorders', jobId);
      if (!job || isDeleted(job)) throw Object.assign(new Error('Active Work Order not found.'), { statusCode:404 });
      const preserved = reconcileWorkOrderDerivedFields({ ...job, isDeleted:false });
      const existingHistory = loadEntityRecordById('fl_workhistory', jobId);
      const archived = normalizeIsDeleted({
        ...(existingHistory || {}),
        ...preserved,
        id: jobId,
        status: safeString(req.body?.reason).trim().toLowerCase() === 'done' ? 'DONE' : 'ARCHIVED',
        completionDate: safeString(req.body?.reason).trim().toLowerCase() === 'done' ? appTodayStr() : safeString(existingHistory?.completionDate || preserved?.completionDate).slice(0,10),
        active: false,
        archived: true,
        archivedAt: Date.now(),
        deletedAt: safeString(req.body?.reason).trim().toLowerCase() === 'deleted' ? new Date().toISOString() : (existingHistory?.deletedAt || preserved?.deletedAt || null),
        updatedAt: new Date().toISOString(),
        archivedReason: safeString(req.body?.reason).trim() || 'deleted',
        isDeleted: false
      });
      const historyResult = await writeEntityRecords('fl_workhistory', [archived]);
      const deleted = normalizeIsDeleted({ ...job, updatedAt:new Date().toISOString(), ...(safeString(req.body?.reason).trim().toLowerCase()==='deleted'?{deletedAt:new Date().toISOString()}:{}), isDeleted:true, active:false, status:'ARCHIVED' });
      validateWorkOrderRecords([deleted]);
      const orderResult = await writeEntityRecords('fl_workorders', [deleted]);
      // Verify both sides of the existing archive flow before reporting success.
      const savedHistory = (Array.isArray(historyResult?.committedRecords) ? historyResult.committedRecords : []).find(x => recordId(x) === jobId);
      const savedOrder = (Array.isArray(orderResult?.committedRecords) ? orderResult.committedRecords : []).find(x => recordId(x) === jobId);
      const isDone = safeString(req.body?.reason).trim().toLowerCase() === 'done';
      const historyMatches = !!savedHistory && (isDone
        ? (safeString(savedHistory.status).toUpperCase() === 'DONE' || safeString(savedHistory.archivedReason).toLowerCase() === 'done')
        : safeString(savedHistory.status).toUpperCase() === 'ARCHIVED');
      const orderMatches = !!savedOrder && isDeleted(savedOrder) && safeString(savedOrder.status).toUpperCase() === 'ARCHIVED';
      if (!historyMatches || !orderMatches) {
        throw Object.assign(new Error('Work Order archive was written but could not be verified in saved state. Please refresh and check the record.'), { statusCode:500 });
      }
      return { historyResult, orderResult, job: savedHistory, verified:true };
    });
    return res.json({ ok:true, preservedHistory:true, ...result });
  } catch (error) {
    console.error('Work order archive failed:', error.message);
    return res.status(error.statusCode || 500).json({ ok:false, error:error.message || 'Could not archive Work Order.' });
  }
});

/* ---------------------------------------------------------
 * Update an existing Leave request status by stable Leave ID.
 * Admin-side Leave approval/decline uses this explicit route so
 * the request cannot fall through to the generic state API.
 * --------------------------------------------------------- */
app.put('/api/state/fl_leaves/:id/status', async (req, res) => {
  const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
  if (!auth) return;

  const id = safeString(req.params.id).trim();
  const requestedStatus = safeString(req.body?.status).trim().toLowerCase();
  const status = requestedStatus === 'rejected' ? 'declined' : requestedStatus;

  if (!id) return res.status(400).json({ ok:false, error:'Leave ID is required.' });
  if (!['approved','declined'].includes(status)) {
    return res.status(400).json({ ok:false, error:'Leave status must be approved or declined.' });
  }

  try {
    const result = await withEntityWriteLock('fl_leaves', async () => {
      const existingRecords = loadEntityAll('fl_leaves');
      const existing = existingRecords.find(record => recordId(record) === id);

      if (!existing || isDeleted(existing)) {
        throw Object.assign(new Error('Leave record not found.'), { statusCode:404 });
      }

      // Merge into the existing record so the same Leave ID and all
      // existing employee/date/reason/submission fields are preserved.
      const updated = mergeEntityRecord('fl_leaves', existing, {
        ...existing,
        id,
        status,
        updatedAt: new Date().toISOString()
      });

      const writeResult = await writeEntityRecords('fl_leaves', [updated]);
      return { writeResult, leave: updated };
    });

    return res.json({ ok:true, ...result });
  } catch (error) {
    console.error('Leave status update failed:', error.message);
    return res.status(error.statusCode || 500).json({
      ok:false,
      error:error.message || 'Could not update Leave status.'
    });
  }
});


/* ---------------------------------------------------------
 * Drawings API — exactly one active encrypted PDF, Admin-side only
 * --------------------------------------------------------- */
const DRAWING_ROLES = ['main_admin','admin_employee','admin_worker'];

app.get('/api/drawings', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    const state = await restoreDrawingsFromGithubIfNeeded();
    return res.json({ok:true,available:Boolean(state.available),fileName:state.index?.fileName||null,updatedAt:state.index?.updatedAt||null,pageCount:state.index?.pages?.length||0,needsOcr:drawingIndexNeedsOcr(state.index),sourceSha:drawingRuntime.sha||null});
  } catch(error) {
    console.error('Drawing status read failed:',error && error.stack ? error.stack : error);
    return res.status(502).json({ok:false,error:'Drawing information is unavailable.',detail:safeString(error?.message).slice(0,300)});
  }
});

app.post('/api/drawings/index', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    const clientPages=Array.isArray(req.body?.pages)?req.body.pages:[];
    if(!clientPages.length) return res.status(400).json({ok:false,error:'Drawing OCR index data is required.'});
    const remotePdf=await githubReadDrawingFile(DRAWING_PDF_GITHUB_FILE);
    if(!remotePdf?.buffer?.length) return res.status(404).json({ok:false,error:'No drawing PDF is currently stored in GitHub.'});
    const expectedSha=safeString(req.body?.sourceSha).trim();
    if(expectedSha && remotePdf.sha && expectedSha!==remotePdf.sha) return res.status(409).json({ok:false,error:'The GitHub drawing PDF changed while OCR was running. Please retry Drawings initialization.'});
    let plainPdf=Buffer.from(remotePdf.buffer);
    if(plainPdf.subarray(0,5).toString('ascii')!=='%PDF-'){
      try { plainPdf=Buffer.from(decryptBuffer(plainPdf)); }
      catch (_) { throw new Error('GitHub drawings.pdf is not a valid PDF.'); }
    }
    if(plainPdf.subarray(0,5).toString('ascii')!=='%PDF-') throw new Error('GitHub drawings.pdf validation failed.');
    const processed=await processDrawingPdf(plainPdf,{sha:remotePdf.sha,updatedAt:new Date().toISOString(),fallbackPages:clientPages});
    if(!processed.available||!processed.index?.pages?.length) throw new Error('Drawing PDF could not be indexed.');
    const payload=Buffer.from(encryptText(JSON.stringify(processed.index,null,2)),'utf8');
    await githubWriteDrawingFile(DRAWING_INDEX_GITHUB_FILE,payload,'Update SOV Engineering drawing OCR index');
    const verifiedIndex=await githubReadDrawingFile(DRAWING_INDEX_GITHUB_FILE);
    if(!verifiedIndex?.buffer?.length) throw new Error('Drawing OCR index could not be verified after GitHub update.');

    // Immediately replace the authenticated runtime index with the exact
    // OCR-processed metadata that was just verified against the current
    // GitHub PDF. Without this update, the very next Search request could
    // still use the pre-OCR in-memory index until a new login/reload.
    drawingRuntime = {
      initialized:true,
      available:true,
      pdf:Buffer.from(remotePdf.buffer.subarray(0,5).toString('ascii') === '%PDF-' ? remotePdf.buffer : decryptBuffer(remotePdf.buffer)),
      index:normalizeDrawingIndex(processed.index),
      sha:remotePdf.sha || null,
      updatedAt:safeString(processed.index.updatedAt || new Date().toISOString())
    };
    try {
      saveDrawingPdfLocal(drawingRuntime.pdf);
      saveDrawingIndexLocal(drawingRuntime.index);
    } catch (cacheError) {
      console.warn('Drawing OCR runtime cache update failed; GitHub remains source of truth:', cacheError.message);
    }

    return res.json({ok:true,pageCount:processed.index.pages.length,updatedAt:processed.index.updatedAt,needsOcr:drawingIndexNeedsOcr(processed.index),sourceSha:remotePdf.sha});
  } catch(error) {
    console.error('Drawing OCR index update failed:',error && error.stack ? error.stack : error);
    return res.status(500).json({ok:false,error:error.message||'Drawing OCR index update failed.'});
  }
});

app.get('/api/drawings/search', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    await restoreDrawingsFromGithubIfNeeded();
    const query=safeString(req.query?.q).trim();
    if(query.length<4) return res.status(400).json({ok:false,error:'Enter at least 4 characters from the drawing number.'});
    const index=drawingRuntime.index;
    const pdf=drawingRuntime.pdf;
    if(!drawingRuntime.available || !index?.pages?.length || !pdf?.length) return res.json({ok:true,query,results:[]});
    const queryKeys=drawingNumberSearchKeys(query);
    const results=[];
    for(const page of index.pages) {
      const candidates=Array.isArray(page.numbers)&&page.numbers.length ? page.numbers : [page.text||''];
      const matched=candidates.some(value=>{
        const keys=drawingNumberSearchKeys(value);
        return keys.some(candidateKey=>queryKeys.some(queryKey=>candidateKey.includes(queryKey)||queryKey.includes(candidateKey)));
      });
      if(matched) results.push({page:page.page,numbers:page.numbers||[],match:query});
    }
    return res.json({ok:true,query,results:results.slice(0,20),pageCount:index.pages.length,fileName:'drawings.pdf'});
  } catch(error) {
    console.error('Drawing search failed:',error.message);
    return res.status(500).json({ok:false,error:'Drawing search failed.'});
  }
});

app.get('/api/drawings/file', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    await restoreDrawingsFromGithubIfNeeded();
    const pdf=drawingRuntime.pdf;
    if(!pdf?.length) return res.status(404).json({ok:false,error:'No drawing PDF is currently uploaded.'});
    if(pdf.subarray(0,5).toString('ascii')!=='%PDF-') throw new Error('Stored drawing PDF verification failed.');
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition','inline; filename="drawings.pdf"');
    res.setHeader('Cache-Control','private, no-store');
    return res.send(pdf);
  } catch(error) {
    console.error('Drawing PDF read failed:',error.message);
    return res.status(500).json({ok:false,error:'Drawing PDF is unavailable.'});
  }
});

app.get('/api/drawings/download', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    await restoreDrawingsFromGithubIfNeeded();
    const pdf=drawingRuntime.pdf;
    if(!pdf?.length) return res.status(404).json({ok:false,error:'No drawing PDF is currently uploaded.'});
    if(pdf.subarray(0,5).toString('ascii')!=='%PDF-') throw new Error('Stored drawing PDF verification failed.');
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition','attachment; filename="drawings.pdf"');
    res.setHeader('Cache-Control','private, no-store');
    return res.send(pdf);
  } catch(error) {
    console.error('Drawing PDF download failed:',error.message);
    return res.status(500).json({ok:false,error:'Drawing PDF is unavailable.'});
  }
});

app.post('/api/drawings/upload', async (req,res) => {
  const auth=requireAuth(req,res,DRAWING_ROLES);
  if(!auth) return;
  try {
    const base64=safeString(req.body?.pdfBase64).replace(/^data:application\/pdf;base64,/i,'').replace(/\s+/g,'');
    if(!base64) return res.status(400).json({ok:false,error:'Drawing PDF is required.'});
    const pdf=Buffer.from(base64,'base64');
    if(!pdf.length || pdf.subarray(0,5).toString('ascii')!=='%PDF-') return res.status(400).json({ok:false,error:'Uploaded file is not a valid PDF.'});
    if(pdf.length>MAX_DRAWING_PDF_BYTES) return res.status(413).json({ok:false,error:`Drawing PDF is too large. Maximum allowed size is ${Math.round(MAX_DRAWING_PDF_BYTES/1024/1024)} MB.`});

    // Always derive searchable metadata from the uploaded PDF server-side when possible.
    // Client-supplied OCR metadata is used only for pages where the server cannot extract text.
    let pages=extractPdfPageTexts(pdf);
    const clientPages=Array.isArray(req.body?.pages)?req.body.pages:[];
    if(clientPages.length && pages.length !== clientPages.length) pages=clientPages.map((page,i)=>({
      page: Math.max(1, Number(page?.page || i + 1)),
      text: safeString(page?.text),
      numbers: Array.isArray(page?.numbers) ? page.numbers : []
    }));
    else if(clientPages.length===pages.length) {
      pages=pages.map((page,i)=>({
        ...page,
        text: page.text || safeString(clientPages[i]?.text),
        numbers: page.numbers.length ? page.numbers : (Array.isArray(clientPages[i]?.numbers)?clientPages[i].numbers:[])
      }));
    }
    if(!pages.length) return res.status(400).json({ok:false,error:'No readable drawing pages were detected in the PDF.'});
    const uploadUpdatedAt=new Date().toISOString();

    ensureDrawingsDir();
    if(!githubConfig()) return res.status(503).json({ok:false,error:'Persistent drawing storage is not configured.'});

    // Prepare independent encrypted representations before touching the active file.
    const drawingPdfPayload=Buffer.from(pdf);
    const previousTargetPdf=await githubReadDrawingFile(DRAWING_PDF_GITHUB_FILE);
    const previousTargetIndex=await githubReadDrawingFile(DRAWING_INDEX_GITHUB_FILE);
    let pdfSaved=false;
    try {
      await githubWriteDrawingFile(DRAWING_PDF_GITHUB_FILE,drawingPdfPayload,'Replace SOV Engineering drawings PDF');
      pdfSaved=true;

      // Read back and verify the exact encrypted target can be decrypted into a valid PDF.
      const verifiedPdf=await githubReadDrawingFileWithRetry(DRAWING_PDF_GITHUB_FILE,4,remote=>{try{const plain=remote.buffer.subarray(0,5).toString('ascii')==='%PDF-'?remote.buffer:decryptBuffer(remote.buffer);return plain.equals(pdf);}catch(_){return false;}});
      if(!verifiedPdf?.buffer?.length) throw new Error('Stored drawing PDF could not be verified.');
      const verifiedPlainPdf = verifiedPdf.buffer.subarray(0,5).toString('ascii') === '%PDF-'
        ? Buffer.from(verifiedPdf.buffer)
        : decryptBuffer(verifiedPdf.buffer);
      if(!verifiedPlainPdf.equals(pdf)) throw new Error('Stored drawing PDF verification failed.');

      // Process the exact verified GitHub PDF through the same common path used
      // during normal initialization. The uploaded client text is supplemental
      // only for PDFs whose page text cannot be extracted server-side.
      const processed = await processDrawingPdf(verifiedPlainPdf, {sha:verifiedPdf.sha, updatedAt:uploadUpdatedAt, fallbackPages:pages});
      if(!processed.available || !processed.index?.pages?.length) throw new Error('Stored drawing PDF could not be indexed.');

      // Persist the exact index produced from the verified GitHub PDF. This is
      // only searchable metadata; drawings.pdf remains the persistent source
      // of truth. The index carries the GitHub blob SHA so it can never be
      // reused for a different PDF.
      const indexPayload=Buffer.from(encryptText(JSON.stringify(processed.index,null,2)),'utf8');
      await githubWriteDrawingFile(DRAWING_INDEX_GITHUB_FILE,indexPayload,'Update SOV Engineering drawing OCR index');
      const verifiedIndex=await githubReadDrawingFile(DRAWING_INDEX_GITHUB_FILE);
      if(!verifiedIndex?.buffer?.length) throw new Error('Stored drawing search index could not be verified.');

      // Immediately activate the verified GitHub PDF + its newly processed
      // OCR/search index for this authenticated runtime. Search must work
      // immediately after upload without another login or page refresh.
      drawingRuntime = {
        initialized:true,
        available:true,
        pdf:Buffer.from(verifiedPlainPdf),
        index:normalizeDrawingIndex(processed.index),
        sha:verifiedPdf.sha || null,
        updatedAt:safeString(processed.index.updatedAt || uploadUpdatedAt)
      };
      try {
        saveDrawingPdfLocal(drawingRuntime.pdf);
        saveDrawingIndexLocal(drawingRuntime.index);
      } catch (cacheError) {
        console.warn('Drawing upload runtime cache update failed; GitHub remains source of truth:', cacheError.message);
      }

      // The new target is now verified. Remove legacy drawing files from the prior implementation;
      // these are related drawing artifacts only and are never application data.
      try { await githubDeleteDrawingFile('current.pdf','Remove legacy SOV Engineering drawings PDF'); } catch (cleanupError) { console.warn('Legacy drawings PDF cleanup failed:',cleanupError.message); }
      try { await githubDeleteDrawingFile('index.json','Remove legacy SOV Engineering drawing index'); } catch (cleanupError) { console.warn('Legacy drawings index cleanup failed:',cleanupError.message); }

      return res.json({ok:true,fileName:'drawings.pdf',pageCount:drawingRuntime.index?.pages?.length||processed.index.pages.length,updatedAt:drawingRuntime.updatedAt||uploadUpdatedAt,needsOcr:drawingIndexNeedsOcr(drawingRuntime.index),sourceSha:drawingRuntime.sha||null,replaced:Boolean(previousTargetPdf?.buffer?.length)});
    } catch(writeError) {
      // Roll back only the drawing target that was changed. The previously valid drawing remains active.
      try {
        if(pdfSaved){
          if(previousTargetPdf?.buffer?.length) await githubWriteDrawingFile(DRAWING_PDF_GITHUB_FILE,previousTargetPdf.buffer,'Rollback SOV Engineering drawings PDF');
          else await githubDeleteDrawingFile(DRAWING_PDF_GITHUB_FILE,'Rollback SOV Engineering drawings PDF');
        }
        try {
          if(previousTargetIndex?.buffer?.length) await githubWriteDrawingFile(DRAWING_INDEX_GITHUB_FILE,previousTargetIndex.buffer,'Rollback SOV Engineering drawing search index');
          else await githubDeleteDrawingFile(DRAWING_INDEX_GITHUB_FILE,'Rollback SOV Engineering drawing search index');
        } catch(indexRollbackError) {
          console.error('Drawing search index rollback failed:',indexRollbackError.message);
        }
      } catch(rollbackError) {
        console.error('Drawing rollback failed:',rollbackError.message);
      }
      throw writeError;
    }
  } catch(error) {
    console.error('Drawing upload failed:',error.message);
    return res.status(500).json({ok:false,error:error.message||'Drawing upload failed.'});
  }
});

/* ---------------------------------------------------------
 * Persistent image-based drawings library. Legacy PDF files and index are
 * intentionally left untouched; new images are additive, encrypted GitHub files.
 * --------------------------------------------------------- */
const DRAWING_IMAGE_MAX_BYTES = Math.max(1, Number(process.env.MAX_DRAWING_IMAGE_MB || 15)) * 1024 * 1024;
const DRAWING_IMAGE_READ_ROLES = ['main_admin','admin_employee','admin_worker','dashboard'];
const DRAWING_IMAGE_WRITE_ROLES = ['main_admin','admin_employee','admin_worker'];
const DRAWING_IMAGE_INDEX = 'images-index.json.enc';
let drawingImageIndexCache = null;
let drawingImageIndexCacheAt = 0;
const DRAWING_IMAGE_INDEX_TTL = 15000;
function normalizeDrawingKey(value) { return safeString(value).normalize('NFKC').toUpperCase().replace(/[^A-Z0-9]/g,''); }
async function readDrawingImageIndex(force=false) {
  if (!force && drawingImageIndexCache && Date.now()-drawingImageIndexCacheAt < DRAWING_IMAGE_INDEX_TTL) return JSON.parse(JSON.stringify(drawingImageIndexCache));
  const remote = await githubReadDrawingFile(DRAWING_IMAGE_INDEX);
  let index = {version:1,updatedAt:'',drawings:[]};
  if (remote?.buffer?.length) {
    let plain;
    try { plain=decryptText(remote.buffer.toString('utf8')); } catch (_) { plain=remote.buffer.toString('utf8'); }
    try { const parsed=JSON.parse(plain); if (Array.isArray(parsed.drawings)) index={version:1,updatedAt:safeString(parsed.updatedAt),drawings:parsed.drawings.filter(x=>x&&typeof x==='object')}; }
    catch (_) { throw new Error('Drawing image index is invalid or corrupted; existing data was not changed.'); }
  }
  drawingImageIndexCache=index; drawingImageIndexCacheAt=Date.now(); return JSON.parse(JSON.stringify(index));
}
async function writeDrawingImageIndex(index) {
  const normalized={version:1,updatedAt:new Date().toISOString(),drawings:(Array.isArray(index.drawings)?index.drawings:[]).map(d=>({...d,number:safeString(d.number).trim(),name:safeString(d.name).trim(),fileName:safeString(d.fileName),mimeType:safeString(d.mimeType),isDeleted:d.isDeleted===true}))};
  const payload=Buffer.from(encryptText(JSON.stringify(normalized,null,2)),'utf8');
  await githubWriteDrawingFile(DRAWING_IMAGE_INDEX,payload,'Update SOV Engineering encrypted drawings image index');
  const verify=await githubReadDrawingFileWithRetry(DRAWING_IMAGE_INDEX,4,remote=>{try{return JSON.stringify(JSON.parse(decryptText(remote.buffer.toString('utf8'))))===JSON.stringify(normalized);}catch(_){return false;}});
  if(!verify?.buffer?.length) throw new Error('Drawing image index could not be verified after saving.');
  const check=JSON.parse(decryptText(verify.buffer.toString('utf8')));
  if(JSON.stringify(check)!==JSON.stringify(normalized)) throw new Error('Drawing image index verification failed.');
  drawingImageIndexCache=normalized; drawingImageIndexCacheAt=Date.now(); return normalized;
}
function safeDrawingImageName(name) { return safeString(name).replace(/[^A-Za-z0-9._-]/g,'_').slice(0,120) || 'drawing-image'; }
app.get('/api/drawings/images', async (req,res)=>{
  if(!requireAuth(req,res,DRAWING_IMAGE_READ_ROLES)) return;
  try { const index=await readDrawingImageIndex(true); const q=safeString(req.query?.q).trim(); const key=normalizeDrawingKey(q); const digits=q.replace(/\D/g,''); const digitsOnly=q.replace(/[\s-]/g,'').length===digits.length; const records=index.drawings.filter(d=>!d.isDeleted).filter(d=>!q||normalizeDrawingKey(d.number).includes(key)||(digitsOnly&&digits.length>=4&&safeString(d.number).replace(/\D/g,'').includes(digits))).sort((a,b)=>safeString(b.uploadedAt).localeCompare(safeString(a.uploadedAt))); return res.json({ok:true,drawings:records.map(({id,number,name,mimeType,size,uploadedAt,updatedAt})=>({id,number,name,mimeType,size,uploadedAt,updatedAt})),total:records.length}); }
  catch(e){console.error('Drawing image list failed:',e.message);return res.status(502).json({ok:false,error:'Drawing image library is unavailable.'});}
});
app.post('/api/drawings/images', async (req,res)=>{
  if(!requireAuth(req,res,DRAWING_IMAGE_WRITE_ROLES)) return;
  try {
    const number=safeString(req.body?.number).trim(); const name=safeString(req.body?.name).trim();
    const declaredMime=safeString(req.body?.mimeType).toLowerCase().split(';')[0].trim();
    const allowed={'image/png':'png','image/jpeg':'jpg','image/jpg':'jpg','image/pjpeg':'jpg','image/webp':'webp'};
    if(!number) return res.status(400).json({ok:false,error:'Drawing number is required.'});
    // Mobile browsers may report image/jpg, image/pjpeg, or an empty/incorrect
    // MIME type. Remove any data-URL prefix generically, then identify the
    // supported format from the actual file signature rather than OCR/content text.
    const encoded=safeString(req.body?.imageBase64).replace(/^data:[^;,]+;base64,/i,'').replace(/\s+/g,'');
    if(!encoded||!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return res.status(400).json({ok:false,error:'The selected file could not be read as an image. Please choose a JPG, JPEG, PNG, or WebP image.'});
    const image=Buffer.from(encoded,'base64'); if(!image.length) return res.status(400).json({ok:false,error:'The selected image is empty or could not be read.'});
    if(image.length>DRAWING_IMAGE_MAX_BYTES) return res.status(413).json({ok:false,error:`Image exceeds the ${Math.round(DRAWING_IMAGE_MAX_BYTES/1024/1024)} MB limit.`});
    const isPng=image.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
    // Valid JPEGs begin with SOI. Do not require EOI to be the final two bytes:
    // some phone/gallery exports append legal trailing metadata after the image.
    const isJpeg=image.length>=3&&image[0]===0xff&&image[1]===0xd8&&image[2]===0xff;
    const isWebp=image.length>=12&&image.subarray(0,4).toString()==='RIFF'&&image.subarray(8,12).toString()==='WEBP';
    const mime=isPng?'image/png':isJpeg?'image/jpeg':isWebp?'image/webp':'';
    if(!mime) return res.status(400).json({ok:false,error:'Unsupported or invalid image file. Please choose a valid JPG, JPEG, PNG, or WebP image.'});
    if(!githubConfig()) return res.status(503).json({ok:false,error:'Persistent GitHub drawing storage is not configured.'});
    const index=await readDrawingImageIndex(true); const key=normalizeDrawingKey(number);
    if(index.drawings.some(d=>!d.isDeleted&&normalizeDrawingKey(d.number)===key)) return res.status(409).json({ok:false,error:'A drawing with this drawing number already exists. Search it or edit the existing record.'});
    const id='drw_'+crypto.randomUUID().replace(/-/g,''); const ext=allowed[mime]; const fileName=`images/${id}.${ext}.enc`; const encrypted=encryptBuffer(image);
    await githubWriteDrawingFile(fileName,encrypted,`Add SOV Engineering drawing image ${id}`);
    const verify=await githubReadDrawingFileWithRetry(fileName,4,remote=>{try{return decryptBuffer(remote.buffer).equals(image);}catch(_){return false;}}); if(!verify?.buffer?.length||!decryptBuffer(verify.buffer).equals(image)){try{await githubDeleteDrawingFile(fileName,'Rollback unverified SOV drawing image');}catch(_){} throw new Error('Uploaded image could not be verified in GitHub.');}
    const record={id,number,name,fileName,mimeType:mime,size:image.length,uploadedAt:new Date().toISOString(),updatedAt:new Date().toISOString(),ocrText:'',isDeleted:false};
    try { index.drawings.push(record); await writeDrawingImageIndex(index); }
    catch(e){try{await githubDeleteDrawingFile(fileName,'Rollback drawing image without committed metadata');}catch(rollback){console.error('Drawing image rollback failed:',rollback.message);}throw e;}
    return res.json({ok:true,drawing:{id,number,name,mimeType:mime,size:image.length,uploadedAt:record.uploadedAt,updatedAt:record.updatedAt}});
  } catch(e){console.error('Drawing image upload failed:',e.message);return res.status(500).json({ok:false,error:e.message||'Drawing image upload failed.'});}
});
app.get('/api/drawings/images/:id/file', async (req,res)=>{
  if(!requireAuth(req,res,DRAWING_IMAGE_READ_ROLES)) return;
  try { const index=await readDrawingImageIndex(); const d=index.drawings.find(x=>x.id===safeString(req.params.id)&&!x.isDeleted); if(!d)return res.status(404).json({ok:false,error:'Drawing image not found.'}); const remote=await githubReadDrawingFile(d.fileName); if(!remote?.buffer?.length) return res.status(404).json({ok:false,error:'Drawing image is missing from persistent storage.'}); const image=decryptBuffer(remote.buffer); res.setHeader('Content-Type',d.mimeType);res.setHeader('Content-Length',image.length);res.setHeader('Cache-Control','private, no-store');return res.send(image); }
  catch(e){console.error('Drawing image read failed:',e.message);return res.status(500).json({ok:false,error:'Drawing image could not be loaded.'});}
});
app.patch('/api/drawings/images/:id', async (req,res)=>{
  if(!requireAuth(req,res,DRAWING_IMAGE_WRITE_ROLES)) return;
  try { const index=await readDrawingImageIndex(true); const d=index.drawings.find(x=>x.id===safeString(req.params.id)&&!x.isDeleted); if(!d)return res.status(404).json({ok:false,error:'Drawing not found.'}); const number=safeString(req.body?.number??d.number).trim(); if(!number)return res.status(400).json({ok:false,error:'Drawing number is required.'}); const key=normalizeDrawingKey(number); if(index.drawings.some(x=>!x.isDeleted&&x.id!==d.id&&normalizeDrawingKey(x.number)===key))return res.status(409).json({ok:false,error:'Another drawing already uses this drawing number.'}); d.number=number;d.name=safeString(req.body?.name??d.name).trim();d.updatedAt=new Date().toISOString();await writeDrawingImageIndex(index);return res.json({ok:true,drawing:{id:d.id,number:d.number,name:d.name,mimeType:d.mimeType,size:d.size,uploadedAt:d.uploadedAt,updatedAt:d.updatedAt}}); }
  catch(e){console.error('Drawing metadata edit failed:',e.message);return res.status(500).json({ok:false,error:'Drawing details could not be saved.'});}
});
app.delete('/api/drawings/images/:id', async (req,res)=>{
  if(!requireAuth(req,res,DRAWING_IMAGE_WRITE_ROLES)) return;
  try { const index=await readDrawingImageIndex(true); const d=index.drawings.find(x=>x.id===safeString(req.params.id)&&!x.isDeleted); if(!d)return res.status(404).json({ok:false,error:'Drawing not found.'}); d.isDeleted=true;d.updatedAt=new Date().toISOString();await writeDrawingImageIndex(index);return res.json({ok:true}); }
  catch(e){console.error('Drawing soft-delete failed:',e.message);return res.status(500).json({ok:false,error:'Drawing could not be deleted.'});}
});

/* Generic state API */

// Targeted record read used by live synchronization. It avoids downloading an
// entire entity collection when another user changes one known record ID.
app.get('/api/state/:key/:id', async (req, res) => {
  const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker']);
  if (!auth) return;
  const requestedKey=safeString(req.params.key).trim();
  const key=requestedKey===EMPLOYEE_KEY || NON_EMPLOYEE_KEYS.includes(requestedKey)
    ? requestedKey
    : migrationEntityAliases(requestedKey);
  const id=safeString(req.params.id).trim();
  if(!key || !id) return res.status(400).json({ok:false,error:'A valid entity and record ID are required.'});
  if(key!==EMPLOYEE_KEY&&!githubStorageReady)return res.status(503).json({ok:false,error:publicBusinessStorageError()});
  try {
    await rolloverDailyStateIfNeeded();
    if(key===EMPLOYEE_KEY){
      const employees=await getEmployeesFromStore(false);
      const found=employees.find(record=>recordId(record)===id && !isDeleted(record));
      if(!found) return res.status(404).json({ok:false,error:'Record not found.'});
      if(auth.role==='worker' && employeeIdOf(found)!==safeString(auth.employeeId)) return res.status(403).json({ok:false,error:'Access denied.'});
      return res.json({ok:true,value:publicEmployees([found])[0]||null,updatedAt:new Date().toISOString()});
    }
    // Prefer the ID-targeted resolver (JSON base + daily + durable recovery
    // overlays). If the warm cache does not contain the record, reconcile once
    // against the authoritative merged entity view before declaring it missing.
    let record=loadEntityRecordById(key,id);
    if(!record){
      const mergedView=loadEntityAll(key);
      record=mergedView.find(item=>recordId(item)===id)||null;
    }
    // Admin live-sync needs to observe a tombstone after an intentional
    // archive/delete. Returning 404 for that known ID makes the client issue a
    // redundant collection read and can race the archive/history update.
    // Keep deleted-record visibility restricted to the same Admin roles that
    // can manage Work Orders; worker reads retain the existing active-only rule.
    if(!record) return res.status(404).json({ok:false,error:'Record not found.',key,id});
    if(isDeleted(record) && !['main_admin','admin_employee','admin_worker'].includes(auth.role)) {
      return res.status(404).json({ok:false,error:'Record not found in the active collection.',key,id});
    }
    const scoped=filterRecordsForAuth(key,[normalizeIsDeleted({...record})],auth);
    if(!scoped.length) return res.status(403).json({ok:false,error:'Access denied.'});
    const employees=await getEmployeesFromStore(false);
    const normalized=normalizeEmployeeReferences(scoped,employees)[0]||null;
    return res.json({ok:true,value:normalized,updatedAt:new Date().toISOString()});
  } catch(error) {
    console.error(`Targeted record read failed for ${key}/${id}:`,error.message);
    return res.status(500).json({ok:false,error:'Record could not be loaded.'});
  }
});

app.get(
  '/api/state/:key',
  async (req, res) => {
    const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker']);
    if (!auth) return;
    const key =
      req.params.key;

    if (key !== EMPLOYEE_KEY && !githubStorageReady) return res.status(503).json({ ok:false, error:publicBusinessStorageError() });

    try {
      await rolloverDailyStateIfNeeded();
      if (key === EMPLOYEE_KEY) {
        const employees = await getEmployeesFromStore(false);
        const visibleEmployees = auth.role==='worker'
          ? employees.filter(employee=>employeeIdOf(employee)===safeString(auth.employeeId)&&employeeActiveOnDateServer(employee))
          : employees;
        return res.json({ value: publicEmployees(visibleEmployees), updatedAt: new Date().toISOString() });
      }

      const records =
        loadEntityAll(key)
          .map(record =>
            normalizeIsDeleted({
              ...record
            })
          )
          .filter(
            record =>
              !isDeleted(record)
          );

      const employees =
        getEmployeesCsv();

      const scopedRecords = filterRecordsForAuth(key, records, auth);
      const normalized =
        normalizeEmployeeReferences(
          scopedRecords,
          employees
        );

      return res.json({
        value:
          normalized,
        updatedAt:
          new Date().toISOString()
      });
    } catch (error) {
      console.error(
        `Read failed for ${key}:`,
        error
      );

      return res
        .status(500)
        .json({
          error:
            'Read failed',
          detail:
            error.message
        });
    }
  }
);

app.put(
  '/api/state/:key',
  async (req, res) => {
    const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker']);
    if (!auth) return;
    const key =
      req.params.key;

    if (key !== EMPLOYEE_KEY && !githubStorageReady) return res.status(503).json({ ok:false, error:githubStorageError || 'GitHub business storage is unavailable.' });

    const value =
      req.body?.value ?? null;

    try {
      if (key === EMPLOYEE_KEY) {
        return res.status(405).json({ ok: false, error: 'Use the Employee API for Employee changes.' });
      }

      const records =
        ensureSoftDeleteField(
          Array.isArray(value)
            ? value
            : []
        ).map(record => key === 'fl_invoices' ? normalizeInvoiceTransactionRecord(record) : record);

            if (auth.role === 'worker') {
        const allowed = new Set(['fl_workorders','fl_attendance','fl_permissions','fl_leaves','fl_sundayot']);
        if (!allowed.has(key)) return res.status(403).json({ok:false,error:'Worker accounts cannot modify this data.'});
        const ownId = safeString(auth.employeeId);
        if (key === 'fl_attendance' && records.some(r=>String(r.employeeId||'')!==ownId)) return res.status(403).json({ok:false,error:'Worker attendance can only be updated for the signed-in employee.'});
        if (['fl_permissions','fl_leaves','fl_sundayot'].includes(key) && records.some(r=>String(r.employeeId||'')!==ownId)) return res.status(403).json({ok:false,error:'Worker records can only be updated for the signed-in employee.'});
        if (key === 'fl_workorders') {
          const latestWorkOrders = loadEntityAll('fl_workorders');
          const latestById = new Map(latestWorkOrders.map(r=>[recordId(r),r]));
          for (const incomingJob of records) {
            const oldJob = latestById.get(recordId(incomingJob));
            if (!oldJob || incomingJob.isDeleted === true || incomingJob.archived === true) return res.status(403).json({ok:false,error:'Worker accounts cannot delete or archive Work Orders.'});
            if (safeString(incomingJob.partName)!==safeString(oldJob.partName) || safeString(incomingJob.workType)!==safeString(oldJob.workType) || Number(incomingJob.total||incomingJob.totalPieces||0)!==Number(oldJob.total||oldJob.totalPieces||0) || safeString(incomingJob.image)!==safeString(oldJob.image)) return res.status(403).json({ok:false,error:'Worker accounts cannot change Work Order master details.'});
            const oldWorks = new Map((Array.isArray(oldJob.works)?oldJob.works:[]).map(w=>[recordId(w),w]));
            for (const incomingWork of (Array.isArray(incomingJob.works)?incomingJob.works:[])) {
              const oldWork=oldWorks.get(recordId(incomingWork));
              if (!oldWork || !assignedIdsServer(oldWork).includes(ownId)) return res.status(403).json({ok:false,error:'Worker accounts can only update their assigned Work records.'});
              if (JSON.stringify(assignedIdsServer(incomingWork).sort())!==JSON.stringify(assignedIdsServer(oldWork).sort())) return res.status(403).json({ok:false,error:'Worker accounts cannot change Work assignments.'});
              if (safeString(incomingWork.title||incomingWork.workName)!==safeString(oldWork.title||oldWork.workName) || safeString(incomingWork.workType)!==safeString(oldWork.workType) || Number(incomingWork.total||incomingWork.totalPieces||0)!==Number(oldWork.total||oldWork.totalPieces||0)) return res.status(403).json({ok:false,error:'Worker accounts cannot change Work master details.'});
              if (JSON.stringify(incomingWork.adminCountAdjustments||[])!==JSON.stringify(oldWork.adminCountAdjustments||[])) return res.status(403).json({ok:false,error:'Worker accounts cannot change Admin count adjustments.'});
              if (String(oldWork.workType || 'PIECE').toUpperCase() === 'PIECE') {
                const incomingOwnDaily = Object.entries(incomingWork.dailyCompleted || {}).filter(([k]) => String(k).endsWith(':' + ownId));
                if (incomingOwnDaily.some(([,v]) => !Number.isFinite(Number(v)) || Number(v) < 0)) {
                  return res.status(400).json({ok:false,error:'Worker count cannot be negative.'});
                }
                if (Number.isFinite(Number(incomingWork.completed)) && Number(incomingWork.completed) < 0) {
                  return res.status(400).json({ok:false,error:'Worker count cannot be negative.'});
                }
              }
              if (String(oldWork.workType || 'PIECE').toUpperCase() === 'PIECE' && String(oldWork.status || 'ACTIVE').toUpperCase() === 'DONE') {
                const oldDailyOwn = Object.fromEntries(Object.entries(oldWork.dailyCompleted || {}).filter(([k]) => String(k).endsWith(':' + ownId)));
                const newDailyOwn = Object.fromEntries(Object.entries(incomingWork.dailyCompleted || {}).filter(([k]) => String(k).endsWith(':' + ownId)));
                const oldHistoryOwn = (Array.isArray(oldWork.completionHistory) ? oldWork.completionHistory : []).filter(x => String(x?.employeeId || '') === ownId);
                const newHistoryOwn = (Array.isArray(incomingWork.completionHistory) ? incomingWork.completionHistory : []).filter(x => String(x?.employeeId || '') === ownId);
                if (JSON.stringify(oldDailyOwn) !== JSON.stringify(newDailyOwn) ||
                    JSON.stringify(oldHistoryOwn) !== JSON.stringify(newHistoryOwn) ||
                    Number(incomingWork.completed || 0) !== Number(oldWork.completed || 0) ||
                    Number(incomingWork.remaining || 0) !== Number(oldWork.remaining || 0) ||
                    String(incomingWork.status || 'ACTIVE').toUpperCase() !== String(oldWork.status || 'ACTIVE').toUpperCase()) {
                  return res.status(403).json({ok:false,error:'Completed Work count cannot be modified.'});
                }
              }
            }
          }
        }
      }

      if (key === 'fl_permissions') {
        for (const record of records) {
          if (!safeString(record.employeeId || record.workerId).trim()) {
            return res.status(400).json({ ok:false, error:'Permission employee ID is required.' });
          }
          if (!/^\d{4}-\d{2}-\d{2}$/.test(safeString(record.date).trim())) {
            return res.status(400).json({ ok:false, error:'Permission date is required.' });
          }
        }
      }

      const result = await withEntityWriteLock(key, async () => {
        const latestRecords = loadEntityAll(key);
        const latestById = new Map(latestRecords.map(r => [recordId(r), r]));
        if (key === 'fl_invoices') {
          validatePendingInwardCompletion(records, latestRecords);
          validatePendingPurchaseOrderCompletion(records, latestRecords);
        }
        let recordsForWrite = records;
        if (key === 'fl_workorders') {
          recordsForWrite = bindAndValidatePendingInwardWorkOrders(records, latestRecords);
          recordsForWrite = bindAndValidatePendingPurchaseOrderWorkOrders(recordsForWrite, latestRecords);
          const rawMergedRecords = recordsForWrite.map(record => {
            const oldRecord = latestById.get(recordId(record));
            const merged = normalizeIsDeleted({ ...(oldRecord || {}), ...(record || {}) });
            const oldWorks = Array.isArray(oldRecord?.works) ? oldRecord.works : [];
            const incomingWorks = Array.isArray(record?.works) ? record.works : [];
            const byWorkId = new Map(oldWorks.filter(w => w && recordId(w)).map(w => [recordId(w), { ...w }]));
            incomingWorks.filter(w => w && recordId(w)).forEach(w => { const id = recordId(w); byWorkId.set(id, mergeNestedWorkRecord(byWorkId.get(id), w)); });
            if (oldRecord?.works || record?.works) merged.works = [...byWorkId.values()];
            return merged;
          });
          validateWorkOrderCountsBeforeReconcile(rawMergedRecords);
        }
        const mergedRecords = recordsForWrite.map(record => mergeEntityRecord(key, latestById.get(recordId(record)), record));
        if (key === 'fl_workorders') validateWorkOrderCounts(mergedRecords);
        const writeResult = await writeEntityRecords(key, mergedRecords);
        return writeResult;
      });

      // Return the verified records from the write operation so the client can
      // reconcile from this response instead of issuing a second GET immediately
      // after every PUT. Keep the same authorization scoping as the read endpoint.
      const persistedRecords = (Array.isArray(result.records) ? result.records : [])
        .map(record => normalizeIsDeleted({ ...record }))
        .filter(record => !isDeleted(record));
      const scopedRecords = filterRecordsForAuth(key, persistedRecords, auth);
      const normalizedValue = normalizeEmployeeReferences(scopedRecords, getEmployeesCsv());
      return res.json({
        ok: true,
        storage: 'json-working-cache',
        synchronization: 'pending-admin-confirmation',
        pending: pendingOperationSummary(),
        monthly: true,
        financialYear: true,
        count: result.count,
        activeCount: result.activeCount,
        deletedCount: result.deletedCount,
        value: normalizedValue,
        updatedAt: new Date().toISOString()
      });
    } catch (error) {
      console.error(
        `Write failed for ${key}:`,
        error
      );

      return res
        .status(500)
        .json({
          error:
            'Write failed: ' + (error.message || 'unknown storage error')
        });
    }
  }
);

/* ---------------------------------------------------------
 * Explicit soft-delete API
 * --------------------------------------------------------- */

app.delete(
  '/api/state/:key/:id',
  async (req, res) => {
    const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker']);
    if (!auth) return;
    const key =
      req.params.key;

    if (key !== EMPLOYEE_KEY && !githubStorageReady) return res.status(503).json({ ok:false, error:githubStorageError || 'GitHub business storage is unavailable.' });

    const id =
      safeString(
        req.params.id
      ).trim();

    if (!id) {
      return res
        .status(400)
        .json({
          ok: false,
          error:
            'Record ID is required.'
        });
    }

    try {
      if (key === EMPLOYEE_KEY) {
        return await withEmployeeWriteLock(async () => {
          const employees = await getEmployeesFromStore(true);
          const index = employees.findIndex(record => recordId(record) === id);
          if (index === -1) return res.status(404).json({ ok:false, error:'Record not found.' });
          employees[index] = normalizeIsDeleted({ ...employees[index], isDeleted:true, active:false });
          await writeEmployeeJsonToGitHub(employees);
          return res.json({ ok:true, softDeleted:true, physicallyDeleted:false });
        });
      }

      const result = await withEntityWriteLock(key, async () => {
        const existing = loadEntityAll(key);
        const found = existing.some(record => recordId(record) === id);
        if (!found) return null;
        const updated = softDeleteRecord(existing, id);
        return await writeEntityRecords(key, updated);
      });

      if(!result) return res.status(404).json({ok:false,error:'Record not found.'});

      return res.json({
        ok: true,
        softDeleted:
          true,
        physicallyDeleted:
          false,
        count:
          result.count,
        activeCount:
          result.activeCount,
        deletedCount:
          result.deletedCount
      });
    } catch (error) {
      console.error(
        `Soft delete failed for ${key}/${id}:`,
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          error:
            'Soft delete failed',
          detail:
            error.message
        });
    }
  }
);

/* ---------------------------------------------------------
 * Single-request state bundle
 * --------------------------------------------------------- */
app.get('/api/state-bundle', async (req, res) => {
  const requestStartedAt = Date.now();
  const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker','dashboard']);
  if (!auth) return;
  if (!githubStorageReady) return res.status(503).json({ ok:false, error:githubStorageError || 'GitHub business storage is unavailable.' });
  try {
    await rolloverDailyStateIfNeeded();
    const employees = await getEmployeesFromStore(false);
      const scopedEmployees = auth.role === 'worker' ? employees.filter(e=>employeeIdOf(e)===safeString(auth.employeeId)&&employeeActiveOnDateServer(e)) : employees;

    // Common Dashboard is a deliberately narrow backend surface and the
    // only authenticated data surface available to the dashboard role. It
    // receives today's records only and never the full operational/admin dataset.
    if (auth.role === 'dashboard') {
      const today = appTodayStr();
      const todayMonth = monthFor(today);
      const todayOnly = key => loadEntityRecordsForFilter(key, { date: today })
        .map(record => normalizeIsDeleted({ ...record }))
        .filter(record => !isDeleted(record))
        .filter(record => recordDate(key, record) === today);
      const todayInvoicesForCommonDashboard = () => loadEntityAll('fl_invoices')
        .map(record => normalizeInvoiceTransactionRecord(record))
        .filter(record => !isDeleted(record))
        .filter(record => {
          const type = safeString(record?.type).trim().toUpperCase();
          if (type === 'INWARD') return recordDate('fl_invoices', record) === today;
          if (type !== 'OUTWARD') return false;
          const mode = safeString(record?.outwardDateMode).trim().toUpperCase();
          if (mode === 'TODAY') {
            const classified = safeString(record?.outwardDashboardDate).slice(0,10);
            if (/^\d{4}-\d{2}-\d{2}$/.test(classified)) return classified === today;
            return recordDate('fl_invoices', record) === today;
          }
          // Mentioned Date and legacy Outwards use the existing transaction date
          // (DC Date / Invoice Date is stored as record.date).
          return recordDate('fl_invoices', record) === today;
        });

      // Work Orders contain master/job information plus nested daily activity.
      // The Common Dashboard needs active job details even when there was no
      // activity today, but it receives only today's nested activity and a
      // derived completion flag rather than the historical daily records.
      // A completed Job Done record is moved from fl_workorders to
      // fl_workhistory. Include today's completed history in the same
      // Common Dashboard work-order surface so Done changes status without
      // deleting/hiding the completed job or today's work activity.
      const commonCurrentOrders = loadEntityAll('fl_workorders')
        .map(record => normalizeIsDeleted({ ...record }))
        .filter(record => !isDeleted(record) && record?.archived !== true)
        .filter(record => { const status=safeString(record?.status).trim().toUpperCase(); return status !== 'DONE' && status !== 'ARCHIVED' && (!record?.date || safeString(record.date).slice(0,10) <= today); });
      const commonTodayHistory = loadEntityAll('fl_workhistory')
        .map(record => normalizeIsDeleted({ ...record }))
        .filter(record => !isDeleted(record))
        .filter(record => {
          const reason = safeString(record?.archivedReason).trim().toLowerCase();
          const status = safeString(record?.status).trim().toUpperCase();
          if (reason !== 'done' && status !== 'DONE') return false;
          const explicit = safeString(record?.completionDate).slice(0,10);
          if (/^\d{4}-\d{2}-\d{2}$/.test(explicit)) return explicit === today;
          const archivedAt = Number(record?.archivedAt || 0);
          if (!Number.isFinite(archivedAt) || archivedAt <= 0) return false;
          try { return new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kolkata'}).format(new Date(archivedAt)) === today; } catch (_) { return false; }
        });
      const commonByJobId = new Map();
      commonCurrentOrders.forEach(record => { const id=recordId(record); if(id) commonByJobId.set(id,record); });
      commonTodayHistory.forEach(record => { const id=recordId(record); if(id) commonByJobId.set(id,record); });
      const commonWorkOrders = [...commonByJobId.values()]
        .map(record => normalizeIsDeleted({ ...record }))
        .filter(record => !isDeleted(record))
        .map(job => {
          const works = (Array.isArray(job.works) ? job.works : []).map(work => {
            const out = { ...work };
            const assigned = assignedIdsServer(work).map(String).filter(Boolean);
            out.dashboardCompleted = assigned.length > 0 && assigned.every(employeeId => {
              const hasCount = Object.keys(work.dailyCompleted || {}).some(key => String(key).endsWith(':' + employeeId));
              const hasWorked = Object.entries(work.workDayRecords || {}).some(([key, value]) => String(key).endsWith(':' + employeeId) && value?.worked === true);
              const hasHistory = (Array.isArray(work.completionHistory) && work.completionHistory.some(item => String(item?.employeeId || '') === employeeId))
                || (Array.isArray(work.correctionHistory) && work.correctionHistory.some(item => String(item?.employeeId || '') === employeeId && item?.worked === true));
              return hasCount || hasWorked || hasHistory;
            });
            const todayKeyPrefix = today + ':';
            if (out.dailyCompleted && typeof out.dailyCompleted === 'object') {
              out.dailyCompleted = Object.fromEntries(Object.entries(out.dailyCompleted).filter(([k]) => String(k).startsWith(todayKeyPrefix)));
            }
            if (out.workDayRecords && typeof out.workDayRecords === 'object') {
              out.workDayRecords = Object.fromEntries(Object.entries(out.workDayRecords).filter(([k]) => String(k).startsWith(todayKeyPrefix)));
            }
            if (Array.isArray(out.completionHistory)) out.completionHistory = out.completionHistory.filter(x => String(x?.date || '') === today);
            if (Array.isArray(out.notWorkedRecords)) out.notWorkedRecords = out.notWorkedRecords.filter(x => String(x?.date || '') === today);
            if (Array.isArray(out.adminCountAdjustments)) out.adminCountAdjustments = out.adminCountAdjustments.filter(x => String(x?.date || '') === today);
            return out;
          });
          return { ...job, works };
        })
        .filter(job => (recordDate('fl_workorders', job) <= today) || (Array.isArray(job.works) && job.works.some(work => {
          const prefix = today + ':';
          return Object.keys(work.dailyCompleted || {}).some(k => String(k).startsWith(prefix))
            || Object.keys(work.workDayRecords || {}).some(k => String(k).startsWith(prefix))
            || (Array.isArray(work.completionHistory) && work.completionHistory.some(x => String(x?.date || '') === today))
            || (Array.isArray(work.notWorkedRecords) && work.notWorkedRecords.some(x => String(x?.date || '') === today));
        })));

      const values = {
        fl_employees: publicEmployees(employees),
        fl_workorders: normalizeEmployeeReferences(commonWorkOrders, employees),
        fl_attendance: normalizeEmployeeReferences(todayOnly('fl_attendance'), employees),
        fl_leaves: normalizeEmployeeReferences(todayOnly('fl_leaves'), employees),
        fl_sundayot: normalizeEmployeeReferences(todayOnly('fl_sundayot'), employees),
        fl_powercuts: todayOnly('fl_powercuts'),
        fl_invoices: todayInvoicesForCommonDashboard()
      };
      return res.json({ ok: true, values, value: values, data: values, currentDate: today, updatedAt: new Date().toISOString() });
    }

    const values = { fl_employees: publicEmployees(scopedEmployees) };
    const failedKeys = [];
    const bundleCacheKey = `${auth.role}:${safeString(auth.employeeId || '')}`;
    const previousBundleValues = lastSuccessfulStateBundleValues.get(bundleCacheKey) || null;
    for (const key of NON_EMPLOYEE_KEYS) {
      try {
        const records = loadEntityAll(key)
          .map(record => normalizeIsDeleted({ ...record }))
          .filter(record => !isDeleted(record));
        const scopedRecords = filterRecordsForAuth(key, records, auth);
        values[key] = normalizeEmployeeReferences(scopedRecords, employees);
      } catch (error) {
        failedKeys.push(key);
        console.error(`State bundle source read failed for ${key}:`, error.message);
        // Keep the last successfully served value for this entity when one
        // source is temporarily unreadable. Never fabricate or delete data.
        if (previousBundleValues && Array.isArray(previousBundleValues[key])) {
          values[key] = previousBundleValues[key].map(record => ({ ...record }));
        } else {
          // There is no safe prior value to substitute on the first request.
          // Omit only this failed optional entity instead of turning every
          // otherwise valid authenticated state source into a 503.
          continue;
        }
      }
    }
    const snapshotForCache = {};
    for (const key of Object.keys(values)) {
      if (Array.isArray(values[key])) snapshotForCache[key] = values[key].map(record => ({ ...record }));
    }
    lastSuccessfulStateBundleValues.set(bundleCacheKey, {
      ...(previousBundleValues || {}),
      ...snapshotForCache
    });
    res.set('Server-Timing', `state-bundle;dur=${Date.now() - requestStartedAt}`);
    return res.json({ ok: true, values, value: values, data: values, currentDate: appTodayStr(), updatedAt: new Date().toISOString() });
  } catch (error) {
    console.error('State bundle read failed:', error.message);
    return res.status(503).json({ ok: false, error: 'Application data is unavailable.' });
  }
});

/* ---------------------------------------------------------
 * Dashboard API
 * --------------------------------------------------------- */

app.get(
  '/api/dashboard',
  async (req, res) => {
    // Common Dashboard has its own minimal /api/state-bundle surface.
    // Never expose the broader Admin Dashboard endpoint to the restricted
    // dashboard role, even when a caller supplies a valid dashboard token.
    const auth = requireAuth(req,res,['main_admin','admin_employee','admin_worker','worker']);
    if (!auth) return;
    try {
      const requested = req.query || {};
      // This broader endpoint is for authenticated operational/admin views.
      // The restricted Common Dashboard role is rejected before this point.
      const from = requested.from;
      const to = requested.to;
      const date = requested.date;
      const month = requested.month;
      const financialYear = requested.financialYear;
      const employeeId = requested.employeeId;
      const partName = requested.partName;
      const status = requested.status;
      const transactionType = requested.transactionType;
      const documentType = requested.documentType;
      const active = requested.active ?? '1';
      const limit = requested.limit ?? '100';

      if (dateRangeExceedsMaxMonths(from, to)) {
        return res.status(400).json({ ok:false, error:`Date range cannot exceed ${MAX_DATE_RANGE_MONTHS} months.` });
      }
      const offset = requested.offset ?? '0';

      const lim =
        Math.min(
          500,
          Math.max(
            1,
            Number(limit) || 100
          )
        );

      const off =
        Math.max(
          0,
          Number(offset) || 0
        );

      const result = {};

      const employees =
        getEmployeesCsv();

      const employeeFilter =
        safeString(
          employeeId
        ).trim();

      /* ---------------------------------------------------
       * Work orders
       * --------------------------------------------------- */

      let works =
        normalizeEmployeeReferences(
          loadEntityByFilter(
            'fl_workorders',
            {
              date,
              month,
              financialYear,
              from,
              to,
              employeeId:
                employeeFilter
            }
          ),
          employees
        );

      works =
        works.filter(work => {
          if (
            active !== '0' &&
            safeString(
              work.status
            ).toUpperCase() ===
              'DONE'
          ) {
            return false;
          }

          if (
            partName &&
            !safeString(
              work.partName
            )
              .toLowerCase()
              .includes(
                safeString(
                  partName
                ).toLowerCase()
              )
          ) {
            return false;
          }

          if (
            status &&
            safeString(
              work.status
            ).toUpperCase() !==
              safeString(
                status
              ).toUpperCase()
          ) {
            return false;
          }

          return true;
        });

      works.sort(
        (a, b) =>
          recordDate(
            'fl_workorders',
            b
          ).localeCompare(
            recordDate(
              'fl_workorders',
              a
            )
          )
      );

      result.works =
        works
          .slice(
            off,
            off + lim
          )
          .map(work => ({
            id:
              work.id,

            partName:
              work.partName,

            workName:
              work.title ||
              work.workName,

            workQuantity:
              work.workQuantity,

            totalPieces:
              Number(
                work.total ||
                work.totalPieces ||
                0
              ),

            completedPieces:
              Number(
                work.completed ||
                work.completedPieces ||
                0
              ),

            remainingPieces:
              Math.max(
                0,
                Number(
                  work.total ||
                  work.totalPieces ||
                  0
                ) -
                  Number(
                    work.completed ||
                    work.completedPieces ||
                    0
                  )
              ),

            status:
              work.status,

            workDate:
              work.date ||
              work.workDate
          }));

      /* ---------------------------------------------------
       * Inward / outward DC / invoice
       * --------------------------------------------------- */

      let transactions =
        normalizeEmployeeReferences(
          loadEntityByFilter(
            'fl_invoices',
            {
              date,
              month,
              financialYear,
              from,
              to
            }
          ),
          employees
        );

      transactions =
        transactions.filter(
          transaction => {
            if (
              transactionType &&
              safeString(
                transaction.type
              ).toUpperCase() !==
                safeString(
                  transactionType
                ).toUpperCase()
            ) {
              return false;
            }

            if (
              documentType &&
              safeString(
                transaction.documentType
              ).toUpperCase() !==
                safeString(
                  documentType
                ).toUpperCase()
            ) {
              return false;
            }

            return true;
          }
        );

      transactions.sort(
        (a, b) =>
          recordDate(
            'fl_invoices',
            b
          ).localeCompare(
            recordDate(
              'fl_invoices',
              a
            )
          )
      );

      result.transactions =
        transactions
          .slice(
            off,
            off + lim
          )
          .map(transaction => ({
            id:
              transaction.id,

            transactionType:
              transaction.type,

            documentType:
              transaction.documentType,

            documentNumber:
              transaction.number ||
              transaction.documentNumber,

            transactionDate:
              transaction.date,

            customerPoNumber:
              safeString(transaction.customerPoNumber).trim(),

            method:
              transaction.method,

            vehicleNumber:
              transaction.vehicleNumber,

            remarks:
              transaction.remarks,

            items:
              Array.isArray(transaction.items)
                ? transaction.items.map(item => ({
                    partName: safeString(item?.partName).trim(),
                    quantity: Number(item?.quantity),
                    remarks: safeString(item?.remarks).trim()
                  })).filter(item => item.partName && Number.isFinite(item.quantity) && item.quantity > 0)
                : [],

            customerDcNumber:
              safeString(transaction.customerDcNumber).trim(),

            status:
              safeString(transaction.status || transaction.invoiceStatus || transaction.workStatus).trim()
          }));

      /* ---------------------------------------------------
       * Optional history
       * --------------------------------------------------- */

      if (
        req.query.includeHistory ===
        '1'
      ) {
        result.workHistory =
          normalizeEmployeeReferences(
            loadEntityByFilter(
              'fl_workhistory',
              {
                date,
                month,
                financialYear,
                from,
                to,
                employeeId:
                  employeeFilter
              }
            ),
            employees
          ).slice(
            off,
            off + lim
          );
      }

      /* ---------------------------------------------------
       * Optional attendance
       * --------------------------------------------------- */

      if (
        req.query.includeAttendance ===
        '1'
      ) {
        result.attendance =
          normalizeEmployeeReferences(
            loadEntityByFilter(
              'fl_attendance',
              {
                date,
                month,
                financialYear,
                from,
                to,
                employeeId:
                  employeeFilter
              }
            ),
            employees
          ).slice(
            off,
            off + lim
          );
      }

      /* ---------------------------------------------------
       * Optional finance
       * --------------------------------------------------- */

      if (
        req.query.includeFinance ===
        '1'
      ) {
        result.finance =
          normalizeEmployeeReferences(
            loadEntityByFilter(
              'fl_finance',
              {
                date,
                month,
                financialYear,
                from,
                to,
                employeeId:
                  employeeFilter
              }
            ),
            employees
          ).slice(
            off,
            off + lim
          );
      }

      if (auth.role === 'worker') {
        const ownId = safeString(auth.employeeId);
        if (Array.isArray(result.works)) result.works = result.works.filter(x=>assignedIdsServer(x).includes(ownId));
        if (Array.isArray(result.workHistory)) result.workHistory = result.workHistory.filter(x=>assignedIdsServer(x).includes(ownId));
        if (Array.isArray(result.attendance)) result.attendance = result.attendance.filter(x=>String(x.employeeId||'')===ownId);
        if (Array.isArray(result.finance)) result.finance = result.finance.filter(x=>String(x.workerId||x.employeeId||'')===ownId);
      }
      return res.json(
        result
      );
    } catch (error) {
      console.error(
        'Dashboard query failed:',
        error
      );

      return res
        .status(500)
        .json({
          error:
            'Dashboard query failed',
          detail:
            error.message
        });
    }
  }
);

/* ---------------------------------------------------------
 * CSV information
 * --------------------------------------------------------- */

app.get(
  '/api/csv-info',
  async (_req, res) => {
    try {
      ensureCsvDirs();

      const index =
        loadIndex();

      return res.json({
        storage:
          'partitioned-json',

        root:
          'data/csv/operational-json',

        jsonBucketsPerMonth:
          JSON_STORE_BUCKETS,

        monthlyFiles:
          [
            ...new Set(
              index
                .map(
                  row =>
                    row.month
                )
                .filter(Boolean)
            )
          ].sort(),

        financialYearFiles:
          [
            ...new Set(
              index
                .map(
                  row =>
                    row.financial_year
                )
                .filter(Boolean)
            )
          ].sort(),

        githubPersistence:
          Boolean(
            githubConfig()
          )
      });
    } catch (error) {
      return res
        .status(500)
        .json({
          error:
            'CSV information failed',
          detail:
            error.message
        });
    }
  }
);

/* ---------------------------------------------------------
 * Health check
 * --------------------------------------------------------- */

app.get(
  '/api/health',
  async (_req, res) => {
    try {
      ensureCsvDirs();
      encryptionKey();

      return res.json({
        ok: true,
        storage:
          'employees-encrypted-github-json-and-operational-partitioned-json-with-csv-recovery',
        operationalJson:
          true,
        jsonStoreBuckets:
          JSON_STORE_BUCKETS,
        encryptedCsv:
          true,
        encryptedEmployeeJson:
          true,
        githubPersistence:
          Boolean(
            githubConfig()
          )
      });
    } catch (error) {
      console.error(
        'Health check failed:',
        error.message
      );

      return res
        .status(503)
        .json({
          ok: false,
          error:
            'Service unavailable'
        });
    }
  }
);

/* ---------------------------------------------------------
 * Static frontend
 * --------------------------------------------------------- */

const PUBLIC_DIR = __dirname;

app.use(
  express.static(PUBLIC_DIR)
);

/* Express 5 compatible SPA fallback. Do not use app.get('*'). */
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }

  const indexFile =
    path.join(PUBLIC_DIR, 'index.html');

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  return res.status(404).send(
    'SOV Engineering application not found.'
  );
});

/* ---------------------------------------------------------
 * Legacy daily JSON migration
 * ---------------------------------------------------------
 * Older deployments may already contain current.json and YYYY-MM-DD.json
 * snapshots. They are imported into the single Previous/Pending buffer once,
 * verified, and then removed. New code never creates date-specific JSON files.
 */
async function backfillMissingRecordIdsAtStartup() {
  const markerPath = 'data/record-id-backfill-v1.json';
  if (githubConfig()) {
    try {
      const marker = await githubReadFile(markerPath);
      if (marker?.content) {
        const parsed = JSON.parse(marker.content);
        if (parsed?.version === 1 && parsed?.complete === true) {
          console.log('Stable record ID backfill already completed; skipping full scan.');
          return { skipped:true, updatedRecords:0, updatedPartitions:0 };
        }
      }
    } catch (error) {
      console.warn('Record ID backfill marker could not be read; running the idempotent backfill:', error.message);
    }
  }

  let updatedRecords = 0;
  let updatedPartitions = 0;
  const changedByEntity = new Map();
  for (const entity of NON_EMPLOYEE_KEYS) {
    const changedFiles = [];
    for (const file of listJsonPartitionFiles(entity)) {
      let raw;
      try { raw = JSON.parse(decryptText(fs.readFileSync(file, 'utf8'))); }
      catch (error) { throw new Error(`Cannot backfill IDs because ${path.relative(JSON_STORE_ROOT, file)} is unreadable: ${error.message}`); }
      if (!Array.isArray(raw)) throw new Error(`Cannot backfill IDs because ${path.relative(JSON_STORE_ROOT, file)} is not an array.`);
      let changed = false;
      const normalized = raw.filter(record => record && typeof record === 'object').map(record => {
        const hadId = !!recordId(record);
        let next = ensureTopLevelRecordId(entity, record, { legacy:true });
        if (!hadId || !sameJsonValue(record, next)) {
          changed = true;
          updatedRecords++;
          // Version the ID-only migration without modifying any existing
          // business timestamp or field.
          next = { ...next, idBackfilledAt:new Date(Math.max(Date.now(), recordSyncTimestamp(record) + 1)).toISOString() };
        }
        return normalizeIsDeleted(next);
      });
      if (!changed) continue;
      writeJsonPartition(file, normalized);
      changedFiles.push(file);
      updatedPartitions++;
    }
    if (changedFiles.length) changedByEntity.set(entity, changedFiles);
  }

  // Pending JSON is also durable state. Give nested legacy rows IDs and commit
  // it before marking the backfill complete; never clear pending records here.
  if (!pendingStateLoaded) await loadPersistentPendingState();
  let pendingChanged = false;
  for (const entity of NON_EMPLOYEE_KEYS) {
    const rows = pendingState.entities[entity] || [];
    const normalized = rows.map(record => {
      let next = ensureTopLevelRecordId(entity, record, { legacy:true });
      if (record?.__legacyIdGenerated || !sameJsonValue(record, next)) {
        pendingChanged = true;
        next = { ...next, idBackfilledAt:new Date(Math.max(Date.now(), recordSyncTimestamp(record) + 1)).toISOString() };
      }
      return next;
    });
    pendingState.entities[entity] = normalized;
  }
  if (pendingChanged) await persistPendingState(pendingState);

  // Mirror only partitions actually changed by the backfill. A failed mirror
  // must prevent the completion marker, allowing a safe retry next startup.
  for (const [entity, files] of changedByEntity) await syncOperationalJsonPartitionsToGitHub(entity, files);
  if (githubConfig()) {
    const marker = JSON.stringify({ version:1, complete:true, completedAt:new Date().toISOString(), updatedRecords, updatedPartitions });
    await githubWriteFile(markerPath, marker, 'Backfill stable IDs for legacy SOV Engineering records');
  }
  console.log(`Stable record ID backfill finished: ${updatedRecords} record(s), ${updatedPartitions} partition(s) updated.`);
  return { skipped:false, updatedRecords, updatedPartitions };
}

async function migrateLegacyDailyJsonToPreviousPending() {
  const legacyRecords = [];
  const localNames = fs.existsSync(DAILY_DIR) ? fs.readdirSync(DAILY_DIR) : [];
  const legacyLocalNames = localNames.filter(name => name === 'current.json' || /^\d{4}-\d{2}-\d{2}\.json$/.test(name));

  for (const name of legacyLocalNames) {
    const parsed = readDailyJsonFile(path.join(DAILY_DIR, name));
    if (parsed?.entities) legacyRecords.push(normalizePendingState(parsed));
  }

  const remoteLegacyPaths = [];
  if (githubConfig()) {
    try {
      const listing = await githubListDirectory(DAILY_JSON_GITHUB_DIR);
      for (const item of listing) {
        const name = safeString(item?.name);
        if (name === 'current.json' || /^\d{4}-\d{2}-\d{2}\.json$/.test(name)) {
          remoteLegacyPaths.push(`${DAILY_JSON_GITHUB_DIR}/${name}`.replace(/^\/+/, ''));
        }
      }
      for (const relativePath of remoteLegacyPaths) {
        try {
          const remote = await githubReadFile(relativePath);
          if (!remote?.content) continue;
          const parsed = JSON.parse(decryptText(remote.content));
          if (parsed?.entities) legacyRecords.push(normalizePendingState(parsed));
        } catch (error) {
          console.error(`Legacy daily JSON migration read failed for ${relativePath}:`, error.message);
        }
      }
    } catch (error) {
      console.error('Legacy daily JSON directory migration read failed:', error.message);
    }
  }

  if (!legacyRecords.length) return false;

  const existingPending = await loadPersistentPendingState();
  let merged = existingPending;
  for (const legacy of legacyRecords) merged = mergePendingStates(merged, legacy);

  // Persist and verify the single buffer before deleting any legacy file.
  await persistPendingState(merged);

  for (const name of legacyLocalNames) {
    try { fs.unlinkSync(path.join(DAILY_DIR, name)); }
    catch (error) { console.error(`Legacy local daily JSON cleanup failed for ${name}:`, error.message); }
  }

  for (const relativePath of remoteLegacyPaths) {
    try {
      await githubDeleteFileIfExists(relativePath, 'Remove legacy SOV Engineering daily JSON after Previous/Pending migration');
    } catch (error) {
      // The consolidated buffer is already verified, so a cleanup failure is
      // non-destructive. The old file is ignored by all new synchronization code.
      console.error(`Legacy remote daily JSON cleanup failed for ${relativePath}:`, error.message);
    }
  }

  console.log(`Migrated ${legacyRecords.length} legacy daily JSON snapshot(s) into the single Previous/Pending JSON buffer.`);
  return true;
}

function loadEntityAllFromJson(entity) { return (yearwiseEntityCache.get(entity)||[]).map(r=>({...r})); }
function dailyOverlayRecords(entity,baseRecords) { return (baseRecords||[]).map(r=>({...r})); }
function loadEntityRecordById(entity,id){return loadEntityAll(entity).find(r=>recordId(r)===String(id))||null;}
function loadEntityRecordsForFilter(entity,filters={}){let rows=loadEntityAll(entity);if(filters.date)rows=rows.filter(r=>recordDate(entity,r)===String(filters.date).slice(0,10));if(filters.from||filters.to){const from=String(filters.from||filters.to).slice(0,10),to=String(filters.to||filters.from).slice(0,10);rows=rows.filter(r=>{const d=recordDate(entity,r);return d>=from&&d<=to;});}if(filters.month)rows=rows.filter(r=>recordDate(entity,r).slice(0,7)===String(filters.month).slice(0,7));if(filters.financialYear){const dates=rows.filter(r=>fyFor(recordDate(entity,r))===filters.financialYear);rows=dates;}return rows;}
async function rolloverDailyStateIfNeeded(){dailyState={date:appTodayStr(),entities:{}};dailyStateLoaded=true;pendingState=emptyPendingState();pendingStateLoaded=true;return dailyState;}
async function writeEntityRecordsUnsafe(entity,records){if(!NON_EMPLOYEE_KEYS.includes(entity))throw new Error('Unknown operational module.');const incoming=ensureSoftDeleteField(Array.isArray(records)?records:[]).filter(r=>r&&typeof r==='object'&&recordId(r)).map(r=>({...r}));const current=new Map(loadEntityAll(entity).map(r=>[recordId(r),{...r}]));const date=appTodayStr();for(const r of incoming){const id=recordId(r),old=current.get(id)||null;const merged=entity==='fl_workorders'?mergeEntityRecord(entity,old,r):mergeRecordsSafely(entity,old,r);current.set(id,normalizeIsDeleted(merged));if(old&&sameJsonValue(normalizeIsDeleted(old),normalizeIsDeleted(merged)))continue;await appendPendingOperation(date,{entity,recordId:id,operationType:!old?'Add':isDeleted(merged)?'Delete':'Edit',changedValues:!old?merged:diffRecordValues(old,merged),originalRecordRef:old?{id,entity}:null,record:merged});}yearwiseEntityCache.set(entity,[...current.values()]);broadcastDataUpdated(entity,incoming.map(recordId).filter(Boolean));const out=[...current.values()].map(normalizeIsDeleted);return {count:out.length,activeCount:out.filter(activeRecord).length,deletedCount:out.filter(isDeleted).length,records:out,committedRecords:incoming.map(r=>current.get(recordId(r))).filter(Boolean)};}
/* ---------------------------------------------------------
 * GitHub year-wise authority and durable single pending operation file
 * --------------------------------------------------------- */
const YEARWISE_RECORDS_ROOT='data/records';
const yearwiseEntityCache=new Map();
const pendingJournals=new Map();
let yearwiseLoadComplete=false;
function diffRecordValues(before,after){const out={};for(const key of new Set([...Object.keys(before||{}),...Object.keys(after||{})]))if(!sameJsonValue(before?.[key],after?.[key])){if(Object.prototype.hasOwnProperty.call(after||{},key))out[key]=after[key];}return out;}
function opYear(op){const d=recordDate(op.entity,op.record||op.changedValues||{});return /^\d{4}-\d{2}-\d{2}$/.test(d)?d.slice(0,4):appTodayStr().slice(0,4);}
function validateYearwiseDocument(doc,year){if(!doc||typeof doc!=='object'||Array.isArray(doc)||!doc.modules||typeof doc.modules!=='object'||Array.isArray(doc.modules))throw new Error('Invalid JSON schema in data/records/sov_'+year+'.json; original file preserved.');if(doc.year!=null&&Number(doc.year)!==Number(year))throw new Error('Year mismatch in data/records/sov_'+year+'.json; original file preserved.');for(const [moduleName,rows] of Object.entries(doc.modules)){if(!Array.isArray(rows))throw new Error('Invalid module data in data/records/sov_'+year+'.json ('+moduleName+'); original file preserved.');const ids=new Set();for(const row of rows){if(!row||typeof row!=='object'||Array.isArray(row)||!recordId(row))throw new Error('Invalid record in data/records/sov_'+year+'.json ('+moduleName+'); original file preserved.');const id=recordId(row);if(ids.has(id))throw new Error('Duplicate record ID in data/records/sov_'+year+'.json ('+moduleName+'); original file preserved.');ids.add(id);}}return doc;}
async function loadYearwiseAuthority(){if(!githubConfig()){yearwiseLoadComplete=true;return;}const response=await githubRepositoryRequest(YEARWISE_RECORDS_ROOT);if(!response)throw new Error('GitHub repository is not configured.');let files=[];if(response.status===404){yearwiseLoadComplete=true;return;}if(!response.ok)throw new Error('Unable to list authoritative year-wise records: '+response.status);files=await response.json();const all=new Map(NON_EMPLOYEE_KEYS.map(k=>[k,new Map()]));for(const file of files.filter(f=>f.type==='file'&&/^sov_\d{4}\.json$/.test(f.name))){const text=await githubReadRepositoryText(YEARWISE_RECORDS_ROOT+'/'+file.name);const doc=validateYearwiseDocument(decryptBusinessJson(text,YEARWISE_RECORDS_ROOT+'/'+file.name),Number(file.name.slice(4,8)));for(const [entity,rows] of Object.entries(doc.modules||{})){if(!all.has(entity)||!Array.isArray(rows))continue;for(const r of rows)if(recordId(r))all.get(entity).set(recordId(r),normalizeIsDeleted({...r}));}}for(const [entity,map] of all)yearwiseEntityCache.set(entity,[...map.values()]);yearwiseLoadComplete=true;}
function yearDocPath(year){return YEARWISE_RECORDS_ROOT+'/sov_'+year+'.json';}
async function readYearDoc(year){const response=await githubRepositoryRequest(yearDocPath(year));if(!response)throw new Error('GitHub repository is not configured.');if(response.status===404)return {doc:{schemaVersion:1,year:Number(year),modules:{}},sha:null};if(!response.ok)throw new Error('Year-wise JSON read failed ('+response.status+').');const body=await response.json();let text='';if(body.content&&body.encoding==='base64')text=Buffer.from(body.content.replace(/\s/g,''),'base64').toString('utf8');else text=await githubReadRepositoryText(yearDocPath(year));return {doc:validateYearwiseDocument(decryptBusinessJson(text,yearDocPath(year)),Number(year)),sha:body.sha||null};}
function applyOperationToYearDoc(doc,op){doc.modules=doc.modules||{};const rows=Array.isArray(doc.modules[op.entity])?doc.modules[op.entity]:[];const map=new Map(rows.map(r=>[recordId(r),r]));if(op.operationType==='Delete')map.set(op.recordId,{...(map.get(op.recordId)||{}),...(op.record||{}),id:op.recordId,isDeleted:true,updatedAt:op.updatedAt});else if(op.record){const old=map.get(op.recordId);const delta=op.operationType==='Add'?op.record:(op.changedValues||op.record);const candidate={...(old||{}),...delta,id:op.recordId};map.set(op.recordId,op.entity==='fl_workorders'?mergeEntityRecord(op.entity,old,candidate):mergeRecordsSafely(op.entity,old,candidate));}doc.modules[op.entity]=[...map.values()];return doc;}
async function commitYearOperations(year,ops){for(let attempt=0;attempt<4;attempt++){const latest=await readYearDoc(year);const doc=latest.doc;doc.schemaVersion=1;doc.year=Number(year);doc.revision=Math.max(0,Number(doc.revision||0))+1;for(const op of ops)applyOperationToYearDoc(doc,op);const config=githubConfig();const body={message:'Synchronize SOV Engineering records '+year+' [skip render]',content:Buffer.from(encryptBusinessJson(doc),'utf8').toString('base64'),branch:config.branch};if(latest.sha)body.sha=latest.sha;const put=await githubRepositoryRequest(yearDocPath(year),{method:'PUT',body:JSON.stringify(body)});if(put.status===409||put.status===422){await new Promise(resolve=>setTimeout(resolve,200*(attempt+1)));continue;}if(!put.ok)throw new Error('Year-wise GitHub write failed: '+put.status+' '+(await put.text()).slice(0,250));let last=null;for(let retry=0;retry<3;retry++){const verify=await readYearDoc(year);if(sameJsonValue(verify.doc,doc)){return doc;}last=new Error('Year-wise record verification mismatch');await new Promise(resolve=>setTimeout(resolve,200*(retry+1)));}if(last)throw last;}throw new Error('Year-wise GitHub update conflicted repeatedly for '+year);}
async function synchronizePendingOperations(){
  if(!githubConfig())throw new Error('GitHub repository storage is not configured.');
  for(const date of [...pendingJournals.keys()])pendingJournals.set(date,await readOperationJournal(date));
  const byYear=new Map();
  for(const [date,journal] of pendingJournals)for(const op of journal.operations.filter(o=>o.status==='pending'||o.status==='failed')){const year=opYear(op);const list=byYear.get(year)||[];list.push({date,op});byYear.set(year,list);}
  const result=[];
  for(const [year,items] of byYear){
    for(let offset=0;offset<items.length;offset+=100){
      const batch=items.slice(offset,offset+100);let status='synced',errorText='';
      try{await commitYearOperations(year,batch.map(x=>x.op));}
      catch(error){status='failed';errorText=String(error.message||error);}
      const byDate=new Map();
      for(const {date,op} of batch){const list=byDate.get(date)||[];list.push(op);byDate.set(date,list);result.push({id:op.id,entity:op.entity,recordId:op.recordId,status,...(errorText?{error:errorText}:{})});}
      for(const [date,ops] of byDate){const journal=pendingJournals.get(date);const ids=new Set(ops.map(o=>o.id));journal.operations=journal.operations.map(o=>ids.has(o.id)?{...o,status,...(status==='synced'?{syncedAt:new Date().toISOString(),error:null}:{error:errorText,updatedAt:new Date().toISOString()})}:o);await saveOperationJournal(journal).catch(error=>{if(status==='synced')throw error;});}
    }
  }
  return result;
}
function pendingOperationSummary(){const operations=[...pendingJournals.values()].flatMap(j=>j.operations);const pending=operations.filter(o=>o.status==='pending'||o.status==='failed');return {count:pending.length,operations:pending.map(o=>({id:o.id,entity:o.entity,recordId:o.recordId,operationType:o.operationType,status:o.status,updatedAt:o.updatedAt,error:o.error||null})),fingerprint:crypto.createHash('sha256').update(pending.map(o=>o.id+':'+o.updatedAt+':'+o.status).sort().join('|')).digest('hex')};}
app.get('/api/admin/pending-operations',async(req,res)=>{const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);if(!auth)return;try{await ensureOperationalStorageReady();await loadPendingJournals();return res.json({ok:true,...pendingOperationSummary()});}catch(error){githubStorageReady=false;githubStorageError=String(error.message||error);console.error('Pending operation check failed:',githubStorageError);return res.status(503).json({ok:false,error:publicBusinessStorageError()});}});
app.get('/api/admin/operation-status/:id',async(req,res)=>{const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);if(!auth)return;try{await loadPendingJournals();const id=String(req.params.id||'');for(const journal of pendingJournals.values()){const operation=journal.operations.find(o=>String(o.id)===id);if(operation)return res.json({ok:true,operation});}return res.status(404).json({ok:false,error:'Operation not found.'});}catch(error){return res.status(503).json({ok:false,error:'Operation status is unavailable.'});}});
app.post('/api/admin/synchronize-pending',async(req,res)=>{const auth=requireAuth(req,res,['main_admin','admin_employee','admin_worker']);if(!auth)return;try{const operations=await synchronizePendingOperations();res.json({ok:true,operations,pending:pendingOperationSummary()});}catch(error){res.status(503).json({ok:false,error:error.message,pending:pendingOperationSummary()});}});

// Single GitHub-authoritative pending file. Its content is never sourced from
// Render's ephemeral disk; every mutation uses the current Contents API SHA.
const SINGLE_PENDING_PATH='data/pending.json';
let singlePendingSyncActive=false;
let singlePendingWriteQueue=Promise.resolve();
let singlePendingSyncSnapshotIds=new Set();
let githubStorageReady=false;
let githubStorageError='GitHub storage is initializing.';
let githubStorageInitialization=null;
function publicBusinessStorageError(){
  if(/DATA_ENCRYPTION_KEY/i.test(githubStorageError))return 'Business-data encryption is not configured on the server. Admin sign-in succeeded, but business records and pending updates are unavailable until the administrator configures DATA_ENCRYPTION_KEY.';
  return 'Business storage is temporarily unavailable. Please retry later or contact the administrator.';
}
function validPendingOperation(op){return !!(op&&typeof op==='object'&&op.id&&op.recordId&&NON_EMPLOYEE_KEYS.includes(op.entity)&&['Add','Edit','Delete','Update'].includes(op.operationType));}
function normalizePendingDocument(value){return {version:1,updatedAt:String(value?.updatedAt||''),operations:(Array.isArray(value?.operations)?value.operations:[]).filter(validPendingOperation).map(o=>({...o,status:['pending','failed'].includes(o.status)?o.status:'pending'}))};}
async function readSinglePending(){const response=await githubRepositoryRequest(SINGLE_PENDING_PATH);if(!response)throw new Error('GitHub repository storage is not configured.');if(response.status===404)return {doc:{version:1,updatedAt:'',operations:[]},sha:null};if(!response.ok){const detail=(await response.text()).slice(0,240);throw new Error('GitHub could not read data/pending.json ('+response.status+'). '+detail);}const body=await response.json();const text=body.content&&body.encoding==='base64'?Buffer.from(body.content.replace(/\s/g,''),'base64').toString('utf8'):await githubReadRepositoryText(SINGLE_PENDING_PATH);const document=decryptBusinessJson(text,SINGLE_PENDING_PATH);validatePendingJson(document);return {doc:normalizePendingDocument(document),sha:body.sha||null};}
function validatePendingJson(doc){if(!doc||typeof doc!=='object'||!Array.isArray(doc.operations))throw new Error('Invalid JSON schema in data/pending.json: expected an operations array.');const ids=new Set();for(const operation of doc.operations){if(!validPendingOperation(operation))throw new Error('Invalid pending operation in data/pending.json; original file preserved.');if(ids.has(String(operation.id)))throw new Error('Duplicate operation ID in data/pending.json; original file preserved.');ids.add(String(operation.id));}}
async function verifyGitHubRepositoryAccess(){const config=githubConfig();if(!config)throw new Error('GitHub storage is not configured. Set GITHUB_TOKEN, GITHUB_REPO, and GITHUB_BRANCH.');let response;try{response=await githubFetchWithTimeout('https://api.github.com/repos/'+config.repo,{headers:{Authorization:'Bearer '+config.token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'sov-engineering-app'}});}catch(error){throw new Error('GitHub connection failed: '+String(error.message||error));}if(response.status===401)throw new Error('GitHub rejected GITHUB_TOKEN (401). Check the token.');if(response.status===403){const remaining=response.headers.get('x-ratelimit-remaining');throw new Error(remaining==='0'?'GitHub API rate limit reached (403).':'GitHub denied repository access (403). Check token Contents permissions.');}if(response.status===404)throw new Error('GitHub repository was not found or is not accessible to this token (404). Check GITHUB_REPO.');if(!response.ok)throw new Error('GitHub repository check failed ('+response.status+'): '+(await response.text()).slice(0,200));}
async function ensureGitHubJsonFile(relativePath,initialValue,validate){for(let attempt=0;attempt<5;attempt++){const response=await githubRepositoryRequest(relativePath);if(!response)throw new Error('GitHub storage is not configured.');if(response.status===404){const config=githubConfig();const body={message:'Initialize SOV Engineering storage '+relativePath,content:Buffer.from(encryptBusinessJson(initialValue),'utf8').toString('base64'),branch:config.branch};const created=await githubRepositoryRequest(relativePath,{method:'PUT',body:JSON.stringify(body)});if(created?.ok){const verify=await githubRepositoryRequest(relativePath);if(!verify?.ok)throw new Error('GitHub did not confirm creation of '+relativePath+' (HTTP '+(verify?.status||'unavailable')+').');const createdBody=await verify.json();const createdText=createdBody.content&&createdBody.encoding==='base64'?Buffer.from(createdBody.content.replace(/\s/g,''),'base64').toString('utf8'):await githubReadRepositoryText(relativePath);let createdJson;try{createdJson=decryptBusinessJson(createdText,relativePath);}catch(_){throw new Error('GitHub created '+relativePath+' but returned invalid JSON.');}validate(createdJson);return createdJson;}if(created&&(created.status===409||created.status===422)){await new Promise(resolve=>setTimeout(resolve,120*(attempt+1)));const concurrent=await githubRepositoryRequest(relativePath);if(concurrent?.ok)continue;const detail=(await created.text()).slice(0,200);throw new Error('GitHub rejected creation of '+relativePath+' ('+created.status+'). '+detail);}const detail=created?(await created.text()).slice(0,200):'No GitHub response.';throw new Error('GitHub could not create '+relativePath+' ('+(created?.status||'unavailable')+'). '+detail);}if(!response.ok){const detail=(await response.text()).slice(0,200);throw new Error('GitHub could not check '+relativePath+' ('+response.status+'). '+detail);}const body=await response.json();const text=body.content&&body.encoding==='base64'?Buffer.from(body.content.replace(/\s/g,''),'base64').toString('utf8'):await githubReadRepositoryText(relativePath);let parsed;try{parsed=decryptBusinessJson(text,relativePath);}catch(error){throw error;}validate(parsed);return parsed;}throw new Error('Could not safely initialize '+relativePath+' after concurrent GitHub updates.');}
async function ensureGitHubTextFile(relativePath, content) {
  for (let attempt=0; attempt<5; attempt++) {
    const current=await githubRepositoryRequest(relativePath);
    if (!current) throw new Error('GitHub storage is not configured.');
    if (current.ok) return false;
    if (current.status!==404) throw new Error('GitHub could not check '+relativePath+' ('+current.status+'): '+(await current.text()).slice(0,200));
    const config=githubConfig();
    const body={message:'Initialize SOV Engineering storage '+relativePath,content:Buffer.from(content,'utf8').toString('base64'),branch:config.branch};
    const created=await githubRepositoryRequest(relativePath,{method:'PUT',body:JSON.stringify(body)});
    if (created?.ok) {
      const verify=await githubRepositoryRequest(relativePath);
      if (!verify?.ok) throw new Error('GitHub did not confirm creation of '+relativePath+' (HTTP '+(verify?.status||'unavailable')+').');
      const saved=await githubReadRepositoryText(relativePath);
      if (saved!==content) throw new Error('GitHub read-back verification failed for '+relativePath+'.');
      return true;
    }
    if (created && (created.status===409 || created.status===422)) {
      const concurrent=await githubRepositoryRequest(relativePath);
      if (concurrent?.ok) return false;
    }
    const detail=created?(await created.text()).slice(0,200):'No GitHub response.';
    throw new Error('GitHub could not create '+relativePath+' ('+(created?.status||'unavailable')+'). '+detail);
  }
  throw new Error('Could not safely initialize '+relativePath+' after concurrent GitHub updates.');
}
async function ensureGitHubRecordsFolder(){
  const response=await githubRepositoryRequest(YEARWISE_RECORDS_ROOT);
  if(!response)throw new Error('GitHub storage is not configured.');
  if(response.ok)return false;
  if(response.status!==404)throw new Error('GitHub could not check data/records/ ('+response.status+'): '+(await response.text()).slice(0,200));
  return ensureGitHubTextFile('data/records/.gitkeep','');
}
async function ensureEncryptedPendingFile(){
  for(let attempt=0;attempt<5;attempt++){
    const current=await githubRepositoryRequest(SINGLE_PENDING_PATH);
    if(!current)throw new Error('GitHub storage is not configured.');
    if(current.status===404){
      const config=githubConfig();
      const body={message:'Initialize encrypted SOV pending operation journal',content:Buffer.from(encryptBusinessJson({version:1,updatedAt:'',operations:[]}),'utf8').toString('base64'),branch:config.branch};
      const created=await githubRepositoryRequest(SINGLE_PENDING_PATH,{method:'PUT',body:JSON.stringify(body)});
      if(created?.ok){const verified=await readSinglePending();if(verified.doc.operations.length!==0)throw new Error('New pending file did not verify as an empty journal.');return true;}
      if(created&&(created.status===409||created.status===422)){await new Promise(resolve=>setTimeout(resolve,120*(attempt+1)));continue;}
      throw new Error('GitHub could not initialize encrypted data/pending.json ('+(created?.status||'unavailable')+').');
    }
    if(!current.ok)throw new Error('GitHub could not check data/pending.json ('+current.status+').');
    await readSinglePending();
    return true;
  }
  throw new Error('Could not safely initialize data/pending.json after concurrent GitHub updates.');
}
async function initializeGitHubStorageStructure(){
  if(githubStorageInitialization)return githubStorageInitialization;
  githubStorageInitialization=(async()=>{
    businessEncryptionKeys();
    await verifyGitHubRepositoryAccess();
    await ensureGitHubRecordsFolder();
    await ensureEncryptedPendingFile();
    githubStorageReady=true;githubStorageError='';return true;
  })().catch(error=>{githubStorageReady=false;githubStorageError=String(error.message||error);throw error;}).finally(()=>{githubStorageInitialization=null;});
  return githubStorageInitialization;
}async function ensureOperationalStorageReady(){await initializeGitHubStorageStructure();if(!yearwiseLoadComplete)await loadYearwiseAuthority();githubStorageReady=true;githubStorageError='';return true;}
async function loadPendingJournals(){const loaded=await readSinglePending();pendingJournals.clear();pendingJournals.set('single',loaded.doc);for(const op of loaded.doc.operations){const rows=yearwiseEntityCache.get(op.entity)||[];const map=new Map(rows.map(r=>[recordId(r),r]));if(op.operationType==='Delete')map.set(String(op.recordId),{...(map.get(String(op.recordId))||op.record||{}),...(op.record||{}),id:String(op.recordId),isDeleted:true,updatedAt:op.updatedAt});else if(op.record)map.set(String(op.recordId),{...op.record});yearwiseEntityCache.set(op.entity,[...map.values()]);}return loaded.doc;}
async function appendPendingOperation(_date,input){if(!githubConfig())throw new Error('GitHub repository storage is not configured. Set GITHUB_TOKEN and GITHUB_REPO.');const task=singlePendingWriteQueue.then(async()=>{for(let attempt=0;attempt<5;attempt++){const current=await readSinglePending();const now=new Date().toISOString();const existing=current.doc.operations.find(o=>o.entity===input.entity&&String(o.recordId)===String(input.recordId)&&!singlePendingSyncSnapshotIds.has(o.id));let operation;if(existing){const operationType=existing.operationType==='Add'?'Add':input.operationType==='Delete'?'Delete':'Update';operation={...existing,operationType,changedValues:operationType==='Add'?(input.record||input.changedValues||{}):diffRecordValues(existing.originalRecord||{},input.record||input.changedValues||{}),record:input.record||null,year:opYear({entity:input.entity,record:input.record||input.changedValues||{}}),updatedAt:now,status:'pending',error:null};}else{const base=(yearwiseEntityCache.get(input.entity)||[]).find(r=>recordId(r)===String(input.recordId));operation={id:crypto.randomUUID(),recordId:String(input.recordId),entity:input.entity,operationType:input.operationType,changedValues:input.changedValues||{},year:opYear({entity:input.entity,record:input.record||input.changedValues||{}}),originalRecordRef:input.originalRecordRef||null,originalRecord:base?{...base}:null,record:input.record||null,createdAt:now,updatedAt:now,status:'pending'};}const operations=[...current.doc.operations.filter(o=>o.id!==existing?.id&&!(o.entity===operation.entity&&String(o.recordId)===String(operation.recordId)&&!singlePendingSyncSnapshotIds.has(o.id))),operation];try{await writeSinglePending({version:1,operations},current.sha,'Record SOV Engineering pending update');return;}catch(error){if(attempt===4)throw error;await new Promise(resolve=>setTimeout(resolve,150*(attempt+1)));}}});singlePendingWriteQueue=task.catch(()=>{});await task;}
async function writeSinglePending(doc,sha,message){const config=githubConfig();const payload=encryptBusinessJson({...doc,updatedAt:new Date().toISOString()});const body={message,content:Buffer.from(payload,'utf8').toString('base64'),branch:config.branch};if(sha)body.sha=sha;const response=await githubRepositoryRequest(SINGLE_PENDING_PATH,{method:'PUT',body:JSON.stringify(body)});if(!response||!response.ok){const detail=response? (await response.text()).slice(0,240):'No GitHub response.';throw new Error('GitHub could not update data/pending.json ('+(response?.status||'unavailable')+'). '+detail);}const saved=await readSinglePending();if(!sameJsonValue(saved.doc.operations,doc.operations))throw new Error('GitHub pending file read-back verification failed.');pendingJournals.set('single',saved.doc);return saved.doc;}
async function synchronizePendingOperations(){if(singlePendingSyncActive)throw new Error('A synchronization is already in progress.');singlePendingSyncActive=true;try{const snapshot=(await readSinglePending()).doc.operations;const eligible=snapshot.filter(o=>['pending','failed'].includes(o.status));singlePendingSyncSnapshotIds=new Set(eligible.map(o=>o.id));const byYear=new Map();for(const op of eligible){const year=String(op.year||opYear(op));const batch=byYear.get(year)||[];batch.push(op);byYear.set(year,batch);}const results=[];const succeeded=new Set();for(const [year,ops] of byYear){try{await commitYearOperations(year,ops);for(const op of ops){succeeded.add(op.id);results.push({id:op.id,recordId:op.recordId,entity:op.entity,status:'synced'});}}catch(error){for(const op of ops)results.push({id:op.id,recordId:op.recordId,entity:op.entity,status:'failed',error:String(error.message||error)});}}for(let attempt=0;attempt<5;attempt++){const latest=await readSinglePending();const nextOps=latest.doc.operations.filter(o=>!succeeded.has(o.id)).map(o=>{const result=results.find(r=>r.id===o.id);return result?.status==='failed'?{...o,status:'failed',error:result.error,updatedAt:new Date().toISOString()}:o;});try{await writeSinglePending({version:1,operations:nextOps},latest.sha,'Finalize SOV Engineering pending synchronization');break;}catch(error){if(attempt===4)throw error;await new Promise(r=>setTimeout(r,150*(attempt+1)));}}await loadPendingJournals();return results;}finally{singlePendingSyncActive=false;singlePendingSyncSnapshotIds=new Set();}}
async function reencryptYearwiseDocuments(){
  const listing=await githubRepositoryRequest(YEARWISE_RECORDS_ROOT);
  if(!listing)throw new Error('GitHub storage is not configured.');
  if(listing.status===404)return 0;
  if(!listing.ok)throw new Error('Could not list year-wise files for key rotation ('+listing.status+').');
  const files=(await listing.json()).filter(f=>f.type==='file'&&/^sov_\d{4}\.json$/.test(f.name));
  for(const file of files){
    const year=Number(file.name.slice(4,8));
    for(let attempt=0;attempt<4;attempt++){
      const latest=await readYearDoc(year);
      const body={message:'Re-encrypt SOV Engineering year-wise records '+year,content:Buffer.from(encryptBusinessJson(latest.doc),'utf8').toString('base64'),branch:githubConfig().branch,sha:latest.sha};
      const saved=await githubRepositoryRequest(yearDocPath(year),{method:'PUT',body:JSON.stringify(body)});
      if(saved?.ok){const verified=await readYearDoc(year);if(!sameJsonValue(verified.doc,latest.doc))throw new Error('Key rotation verification failed for '+file.name+'.');break;}
      if((saved?.status===409||saved?.status===422)&&attempt<3){await new Promise(resolve=>setTimeout(resolve,180*(attempt+1)));continue;}
      throw new Error('Could not re-encrypt '+file.name+' ('+(saved?.status||'unavailable')+').');
    }
  }
  return files.length;
}
app.post('/api/admin/reencrypt-storage',async(req,res)=>{
  const auth=requireAuth(req,res,['main_admin']);if(!auth)return;
  try{
    businessEncryptionKeys();
    const years=await reencryptYearwiseDocuments();
    const pending=await readSinglePending();
    await writeSinglePending(pending.doc,pending.sha,'Re-encrypt SOV pending operation journal');
    return res.json({ok:true,yearFiles:years,pendingFile:true});
  }catch(error){return res.status(503).json({ok:false,error:'Storage key rotation did not finish. Existing files and pending operations were preserved where not yet verified.'});}
});

function pendingOperationSummary(){const operations=pendingJournals.get('single')?.operations||[];const pending=operations.filter(o=>['pending','failed'].includes(o.status));return {count:pending.length,operations:pending.map(o=>({id:o.id,entity:o.entity,recordId:o.recordId,operationType:o.operationType,status:o.status,updatedAt:o.updatedAt,error:o.error||null})),modules:[...new Set(pending.map(o=>o.entity))],fingerprint:crypto.createHash('sha256').update(pending.map(o=>o.id+':'+o.updatedAt+':'+o.status).sort().join('|')).digest('hex')};}

/* ---------------------------------------------------------
 * Startup
 * --------------------------------------------------------- */

(async () => {
  try {
    ensureCsvDirs();

    /*
     * Restore durable encrypted CSV files from GitHub before serving requests.
     * Startup is intentionally read/merge-only; it must not push operational
     * data back to GitHub or create a deployment-triggering commit.
     */
    encryptionKey();
    try {
      await ensureOperationalStorageReady();
      await loadPendingJournals();
    } catch (storageStartupError) {
      githubStorageReady = false;
      githubStorageError = String(storageStartupError.message || storageStartupError);
      console.error('GitHub storage is unavailable; business data APIs will return this storage error until recovery:', githubStorageError);
    }
    await rolloverDailyStateIfNeeded();
    // Drawings are durable in the private GitHub repository. Render's local
    // drawings cache is disposable, so restore it when possible without ever
    // deleting/resetting the persistent GitHub drawing. A transient GitHub
    // outage must not prevent the application from starting.
    try {
      await restoreDrawingsFromGithubIfNeeded({forceRemote:true});
    } catch (drawingStartupError) {
      console.error('Drawing startup restore failed; persistent GitHub drawing was not modified:', drawingStartupError.message);
    }
    // Employee authentication retains its existing store; no employee CSV migration is run at startup.

    app.listen(
      port,
      () => {
        console.log(
          `SOV Engineering server listening on ${port}`
        );

        console.log(
          'Storage architecture: operational modules use GitHub-authoritative data/records/sov_YYYY.json documents; the single data/pending.json file is synchronized only after explicit Admin confirmation; CSV is retained for backup/export only.'
        );

        console.log(
          `CSV directory: ${CSV_ROOT}`
        );

        console.log(
          `GitHub CSV persistence: ${
            githubConfig()
              ? 'enabled'
              : 'disabled'
          }`
        );
      }
    );
  } catch (error) {
    console.error(
      'Server startup failed:',
      error
    );

    process.exit(1);
  }
})();
