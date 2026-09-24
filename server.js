// ============================================================
//  LICA — Node.js API Server
//  Pola sama dengan CV AI project (localhost:3001)
//  Pakai port 3001 supaya tidak bentrok sama CV AI (3000)
// ============================================================

const express  = require('express');
const { Pool } = require('pg');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const crypto   = require('crypto');

const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── MIDDLEWARE ──────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Serve frontend HANYA dari folder public/ (jangan expose root repo)
app.use(express.static(path.join(__dirname, 'public')));

// ── DB CONNECTION (Railway PostgreSQL) ─────────────────────
// Kredensial dari env var (set di Railway > Variables, atau file .env di local)
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL belum di-set');
  process.exit(1);
}
const useSSL = !process.env.DATABASE_URL.includes('.railway.internal');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

// Test koneksi saat startup
pool.query('SELECT NOW()', (err, res) => {
  if (err) console.error('❌ DB connection failed:', err.message);
  else     console.log('✅ DB connected:', res.rows[0].now);
});

// Helper query dengan schema istana_surya
const q = (text, params) => pool.query(text, params);

// ── AUTH MIDDLEWARE ─────────────────────────────────────────
async function requireAuth(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'No token' });

  // Mock token — langsung lolos, ambil user dari header X-Mock-User jika ada
  if (token.startsWith('mock_')) {
    req.user = {
      role:      req.headers['x-user-role']     || 'admin',
      full_name: req.headers['x-user-fullname'] || 'Dev User',
      username:  req.headers['x-user-name']     || 'dev',
    };
    return next();
  }

  try {
    const result = await q(
      `SELECT u.id AS user_id, u.full_name, u.username, u.role
       FROM istana_surya.user_sessions s
       JOIN istana_surya.users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.expires_at > NOW() AND u.is_active = TRUE`,
      [token]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid/expired token' });
    req.user = result.rows[0];
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ════════════════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username & password required' });

  try {
    const result = await q(
      `SELECT id, full_name, username, password, role, is_active
       FROM istana_surya.users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (!user || !user.is_active) return res.status(401).json({ message: 'Username atau password salah.' });

    // Plain text comparison (sementara, nanti migrate ke bcrypt)
    const match = password === user.password;
    if (!match) return res.status(401).json({ message: 'Username atau password salah.' });

    // Buat token
    const token = crypto.randomBytes(32).toString('hex');
    await q(
      `INSERT INTO istana_surya.user_sessions(user_id, token, ip_address)
       VALUES ($1, $2, $3)`,
      [user.id, token, req.ip]
    );
    await q(`UPDATE istana_surya.users SET last_login_at = NOW() WHERE id = $1`, [user.id]);

    res.json({
      token,
      user: { full_name: user.full_name, username: user.username, role: user.role }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  try {
    await q(`DELETE FROM istana_surya.user_sessions WHERE token = $1`, [token]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ════════════════════════════════════════════════════════════
//  USERS (admin only)
// ════════════════════════════════════════════════════════════

// GET /api/users
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await q(
      `SELECT id, full_name, username, role, is_active, last_login_at, created_at
       FROM istana_surya.users ORDER BY id`
    );
    res.json({ users: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/users
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { full_name, username, password, role } = req.body;
  if (!full_name || !username || !password) return res.status(400).json({ error: 'Required fields missing' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await q(
      `INSERT INTO istana_surya.users(full_name, username, password, role)
       VALUES ($1,$2,$3,$4) RETURNING id, full_name, username, role`,
      [full_name, username, hash, role || 'csr']
    );
    res.json(result.rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username sudah dipakai.' });
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/users/:id
app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { full_name, username, password, role } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      await q(`UPDATE istana_surya.users SET full_name=$1,username=$2,password=$3,role=$4 WHERE id=$5`,
        [full_name, username, hash, role, req.params.id]);
    } else {
      await q(`UPDATE istana_surya.users SET full_name=$1,username=$2,role=$3 WHERE id=$4`,
        [full_name, username, role, req.params.id]);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/users/:id  (toggle active)
app.patch('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await q(`UPDATE istana_surya.users SET is_active=$1 WHERE id=$2`, [req.body.is_active, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
//  DEBUG — cek isi kedua tabel (admin only, hapus di production)
// ════════════════════════════════════════════════════════════
app.get('/api/debug/sync', requireAuth, requireAdmin, async (req, res) => {
  try {
    const ocr = await q(`SELECT file_id, LEFT(base64_pdf,10) AS pdf_preview, total_confidence FROM istana_surya.document_ocr_detail ORDER BY id`);
    const upl = await q(`SELECT file_id, nama_doc, status, uploaded_at FROM istana_surya.upload_documents ORDER BY id`);
    const matched = ocr.rows.filter(o => upl.rows.some(u => u.file_id === o.file_id));
    const orphanOcr = ocr.rows.filter(o => !upl.rows.some(u => u.file_id === o.file_id));
    const orphanUpl = upl.rows.filter(u => !ocr.rows.some(o => o.file_id === u.file_id));
    res.json({ ocr: ocr.rows, upload: upl.rows, matched, orphanOcr, orphanUpl });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/debug/fix-sync — auto-create upload_documents entries for orphan OCR records
app.post('/api/debug/fix-sync', requireAuth, requireAdmin, async (req, res) => {
  try {
    // Cari OCR record yang tidak punya pasangan di upload_documents
    const orphans = await q(`
      SELECT o.file_id, o.so_number, o.no_po_ref, o.nama_perusahaan, o.total_confidence
      FROM istana_surya.document_ocr_detail o
      WHERE o.file_id NOT IN (SELECT file_id FROM istana_surya.upload_documents)
    `);

    const inserted = [];
    for (const row of orphans.rows) {
      const conf = parseFloat(row.total_confidence || 0);
      const status = conf >= 90 ? 'menunggu_review' : 'antrian_manual';
      // Gunakan so_number atau no_po_ref sebagai nama file
      const docRef = row.so_number || row.no_po_ref;
      const nama_doc = docRef
        ? `${docRef}.pdf`
        : `doc-${row.file_id.slice(0,8)}.pdf`;
      await q(
        `INSERT INTO istana_surya.upload_documents(file_id, nama_doc, status, uploaded_by)
         VALUES ($1, $2, $3, 'system-sync')
         ON CONFLICT (file_id) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()`,
        [row.file_id, nama_doc, status]
      );
      inserted.push({ file_id: row.file_id, nama_doc, status });
    }
    res.json({ ok: true, fixed: inserted.length, rows: inserted });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════════════════════

// GET /api/dashboard/stats  — sumber: istana_surya.upload_documents
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        COUNT(*)                                                                                        AS total,
        COUNT(*) FILTER (WHERE o.status = 'successfully_sent_to_sap_b1')                               AS sap,
        COUNT(*) FILTER (WHERE o.status IN ('menunggu_review','menunggu review','on_progres','on_progress')) AS pending,
        COUNT(*) FILTER (WHERE o.status IN ('antrian_manual','antrian manual'))                         AS manual,
        COUNT(*) FILTER (WHERE o.status = 'approved')                                                   AS approved,
        COUNT(*) FILTER (WHERE o.status = 'rejected')                                                   AS rejected,
        COUNT(*) FILTER (WHERE o.status = 'failed_sent_to_sap_b1')                                     AS failed_sap
      FROM istana_surya.document_ocr_detail o
    `);
    const r = result.rows[0];
    res.json({
      total:      parseInt(r.total),
      sap:        parseInt(r.sap),
      pending:    parseInt(r.pending),
      manual:     parseInt(r.manual),
      approved:   parseInt(r.approved),
      rejected:   parseInt(r.rejected),
      failed_sap: parseInt(r.failed_sap),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/dashboard/chart-7d  — sumber: istana_surya.upload_documents + istana_surya.document_ocr_detail
app.get('/api/dashboard/chart-7d', requireAuth, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        TO_CHAR(u.uploaded_at::TIMESTAMPTZ AT TIME ZONE 'Asia/Jakarta', 'Dy') AS day,
        COUNT(*) FILTER (WHERE o.tipe = 'SO') AS so,
        COUNT(*) FILTER (WHERE o.tipe = 'PO') AS po
      FROM istana_surya.upload_documents u
      LEFT JOIN istana_surya.document_ocr_detail o ON o.file_id = u.file_id
      WHERE u.uploaded_at::TIMESTAMPTZ >= NOW() - INTERVAL '7 days'
      GROUP BY TO_CHAR(u.uploaded_at::TIMESTAMPTZ AT TIME ZONE 'Asia/Jakarta', 'Dy'),
               DATE_TRUNC('day', u.uploaded_at::TIMESTAMPTZ AT TIME ZONE 'Asia/Jakarta')
      ORDER BY DATE_TRUNC('day', u.uploaded_at::TIMESTAMPTZ AT TIME ZONE 'Asia/Jakarta')
    `);
    res.json(result.rows.map(r => ({
      day: r.day,
      so:  parseInt(r.so),
      po:  parseInt(r.po),
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/dashboard/pending
// Sumber MURNI: istana_surya.upload_documents saja — tanpa JOIN ke OCR
// Deduplikasi by file_id (ambil row terbaru), parse tipe dari nama_doc
app.get('/api/dashboard/pending', requireAuth, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        o.id          AS ocr_id,
        o.file_id,
        u.nama_doc,
        o.status,
        u.uploaded_by,
        u.uploaded_at,
        o.updated_at,
        CASE
          WHEN UPPER(u.nama_doc) LIKE '%PO%' THEN 'PO'
          WHEN UPPER(u.nama_doc) LIKE '%SO%' THEN 'SO'
          ELSE '—'
        END AS tipe_parsed
      FROM istana_surya.document_ocr_detail o
      JOIN istana_surya.upload_documents u ON u.file_id = o.file_id
      WHERE o.status IN (
        'menunggu_review','menunggu review',
        'antrian_manual','antrian manual',
        'on_progres','on_progress'
      )
      ORDER BY o.updated_at DESC NULLS LAST
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
//  DOCUMENTS
// ════════════════════════════════════════════════════════════

// GET /api/documents?status=menunggu_review,antrian_manual,on_progres
// Sumber: istana_surya.upload_documents INNER JOIN istana_surya.document_ocr_detail
// Hanya tampilkan dokumen yang sudah ada data OCR-nya
app.get('/api/documents', requireAuth, async (req, res) => {
  try {
    const statuses = req.query.status ? req.query.status.split(',') : null;
    let text = `
      SELECT
        u.id,
        u.file_id,
        o.id                                AS ocr_id,
        u.nama_doc,
        u.nama_doc                          AS file_path,
        o.status,
        u.uploaded_by,
        u.uploaded_at,
        o.updated_at,
        o.tipe                              AS document_type,
        o.customer                          AS vendor_customer_name,
        o.subtotal                          AS total_value,
        o.total_confidence                  AS ocr_confidence_score,
        o.nama_perusahaan,
        o.tanggal_dokumen,
        o.alamat,
        o.so_number,
        o.no_po_ref,
        o.nama_item,
        o.total_item,
        o.harga_per_item,
        o.akurasi_po_header,
        o.akurasi_item,
        o.processed_at
      FROM istana_surya.upload_documents u
      INNER JOIN istana_surya.document_ocr_detail o ON o.file_id = u.file_id
    `;
    let params = [];
    const conditions = [];

    // Filter by file_id jika ada (dari dashboard → hanya cards untuk 1 file)
    const fileIdFilter = req.query.file_id;
    if (fileIdFilter) {
      params.push(fileIdFilter);
      conditions.push(`u.file_id = $${params.length}`);
    }

    if (statuses) {
      const expanded = [];
      statuses.forEach(s => {
        expanded.push(s);
        expanded.push(s.replace(/_/g, ' '));
        expanded.push(s.replace(/ /g, '_'));
      });
      const unique = [...new Set(expanded)];
      params.push(unique);
      conditions.push(`o.status = ANY($${params.length}::TEXT[])`);
    }

    if (conditions.length) {
      text += ` WHERE ` + conditions.join(' AND ');
    }
    text += ` ORDER BY o.updated_at DESC`;
    const result = await q(text, params);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/documents/history
app.get('/api/documents/history', requireAuth, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        u.id,
        u.file_id,
        o.id                                AS ocr_id,
        u.nama_doc,
        u.nama_doc                          AS file_path,
        o.status,
        u.uploaded_by,
        u.uploaded_at,
        o.updated_at,
        o.tipe                              AS document_type,
        o.customer                          AS vendor_customer_name,
        o.subtotal                          AS total_value,
        o.total_confidence                  AS ocr_confidence_score,
        o.nama_perusahaan,
        o.tanggal_dokumen,
        o.alamat,
        o.so_number,
        o.no_po_ref,
        o.nama_item,
        o.total_item,
        o.harga_per_item
      FROM istana_surya.upload_documents u
      INNER JOIN istana_surya.document_ocr_detail o ON o.file_id = u.file_id
      ORDER BY o.updated_at DESC
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/documents/:id/review
// :id bisa berupa u.id (integer) atau u.file_id (text)
app.get('/api/documents/:id/review', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Step 1: ambil data tanpa base64 dulu (bisa sangat besar)
    const result = await q(`
      SELECT
        u.id,
        u.file_id,
        o.id                                AS ocr_id,
        u.nama_doc,
        u.nama_doc                          AS file_path,
        u.status,
        u.uploaded_by,
        u.uploaded_at,
        u.updated_at,
        o.tipe                              AS document_type,
        o.customer,
        o.subtotal                          AS total_value,
        o.total_confidence                  AS ocr_confidence_score,
        o.nama_perusahaan,
        o.tanggal_dokumen,
        o.alamat,
        o.so_number,
        o.no_po_ref,
        o.nama_item,
        o.total_item,
        o.harga_per_item,
        o.akurasi_po_header,
        o.akurasi_item,
        o.akurasi_nama_perusahaan,
        o.akurasi_tipe,
        o.akurasi_tanggal,
        o.akurasi_customer,
        o.akurasi_alamat,
        o.akurasi_nama_item,
        o.akurasi_total_item,
        o.akurasi_harga_per_item,
        o.akurasi_subtotal,
        o.akurasi_no_po_ref,
        o.lica_notes,
        o.processed_at
      FROM istana_surya.upload_documents u
      LEFT JOIN istana_surya.document_ocr_detail o ON o.file_id = u.file_id
      WHERE o.id::TEXT = $1 OR u.file_id = $1 OR u.id::TEXT = $1
      LIMIT 1
    `, [id]);

    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const row = result.rows[0];

    // Step 2: ambil base64_pdf terpisah (kolom besar) + deteksi mime type
    let base64_pdf  = null;
    let file_mime   = 'application/pdf'; // default
    try {
      const pdfResult = await q(
        `SELECT base64_pdf FROM istana_surya.document_ocr_detail WHERE id = $1 LIMIT 1`,
        [row.ocr_id]
      );
      base64_pdf = pdfResult.rows[0]?.base64_pdf || null;

      if (base64_pdf) {
        // Kalau sudah ada data: prefix, pakai langsung
        if (base64_pdf.startsWith('data:')) {
          const mimeMatch = base64_pdf.match(/^data:([^;]+);base64,/);
          file_mime  = mimeMatch ? mimeMatch[1] : 'application/pdf';
          // Hapus prefix — simpan raw base64 saja, prefix dibangun di frontend
          base64_pdf = base64_pdf.replace(/^data:[^;]+;base64,/, '');
        } else {
          // Raw base64 tanpa prefix → deteksi dari magic bytes
          // Decode 8 byte pertama untuk cek signature
          try {
            const buf    = Buffer.from(base64_pdf.slice(0, 16), 'base64');
            const hex    = buf.toString('hex').toUpperCase();
            if      (hex.startsWith('25504446'))         file_mime = 'application/pdf';  // %PDF
            else if (hex.startsWith('FFD8FF'))           file_mime = 'image/jpeg';        // JPEG
            else if (hex.startsWith('89504E47'))         file_mime = 'image/png';         // PNG
            else if (hex.startsWith('47494638'))         file_mime = 'image/gif';         // GIF
            else if (hex.startsWith('52494646'))         file_mime = 'image/webp';        // RIFF/WebP
            else                                         file_mime = 'application/pdf';   // fallback
          } catch {
            file_mime = 'application/pdf';
          }
        }
      }
    } catch (pdfErr) {
      console.warn('⚠️  base64_pdf fetch failed:', pdfErr.message);
    }

    // Step 3: build fields
    const conf = (val) => (val == null ? 'high' : parseFloat(val) >= 85 ? 'high' : 'low');

    let namaItem = [], totalItem = [], hargaItem = [];
    try {
      // nama_item di DB adalah TEXT (bisa plain string atau JSON array string)
      // total_item = int4 (single value), harga_per_item = int8 (single value)
      const rawNama  = row.nama_item;
      const rawTotal = row.total_item;
      const rawHarga = row.harga_per_item;

      if (rawNama) {
        if (Array.isArray(rawNama)) {
          namaItem = rawNama;
        } else if (typeof rawNama === 'string' && rawNama.trim().startsWith('[')) {
          namaItem = JSON.parse(rawNama);
        } else {
          // Plain text — satu item saja
          namaItem = [rawNama];
        }
      }

      if (rawTotal != null) {
        if (Array.isArray(rawTotal)) {
          totalItem = rawTotal;
        } else if (typeof rawTotal === 'string' && rawTotal.trim().startsWith('[')) {
          totalItem = JSON.parse(rawTotal);
        } else {
          totalItem = [rawTotal];
        }
      }

      if (rawHarga != null) {
        if (Array.isArray(rawHarga)) {
          hargaItem = rawHarga;
        } else if (typeof rawHarga === 'string' && rawHarga.trim().startsWith('[')) {
          hargaItem = JSON.parse(rawHarga);
        } else {
          hargaItem = [rawHarga];
        }
      }
    } catch(jsonErr) {
      console.warn('⚠️  parse error on item fields:', jsonErr.message);
    }

    const fmtRp = (v) => v != null ? `Rp ${parseFloat(v).toLocaleString('id-ID')}` : '—';

    const fields = [
      { k: 'Nama Perusahaan', v: row.nama_perusahaan || '—', c: conf(row.akurasi_nama_perusahaan), pct: row.akurasi_nama_perusahaan, col: 'nama_perusahaan', editable: true },
      { k: 'Tipe Dokumen',    v: row.document_type   || '—', c: conf(row.akurasi_tipe),             pct: row.akurasi_tipe,            col: 'tipe',           editable: true },
      { k: 'Tanggal Dokumen', v: row.tanggal_dokumen ? new Date(row.tanggal_dokumen).toLocaleDateString('id-ID') : '—',
                                                              c: conf(row.akurasi_tanggal),          pct: row.akurasi_tanggal,         col: 'tanggal_dokumen', editable: true },
      { k: 'Customer',        v: row.customer        || '—', c: conf(row.akurasi_customer),          pct: row.akurasi_customer,        col: 'customer',       editable: true },
      { k: 'Alamat',          v: row.alamat          || '—', c: conf(row.akurasi_alamat),            pct: row.akurasi_alamat,          col: 'alamat',         editable: true },
      { k: 'No. SO/PO',       v: row.so_number || row.no_po_ref || '—', c: conf(row.akurasi_no_po_ref), pct: row.akurasi_no_po_ref, col: 'so_number', editable: true },
      { k: 'Subtotal',        v: fmtRp(row.total_value),     c: conf(row.akurasi_subtotal),          pct: row.akurasi_subtotal,        col: 'subtotal',       editable: true },
      ...namaItem.map((nama, i) => ({
        k: namaItem.length > 1 ? `Item ${i + 1}` : 'Item',
        v: `${nama} · Qty: ${totalItem[i] ?? '—'} · ${fmtRp(hargaItem[i])}`,
        c: conf(row.akurasi_nama_item),
        pct: row.akurasi_nama_item,
        col: `item_${i}`,
        editable: false,
      })),
      // LICA Notes — catatan manual dari reviewer
      ...(row.lica_notes != null ? [{
        k: 'LICA Notes',
        v: row.lica_notes || '—',
        c: 'high',
        pct: null,
        col: 'lica_notes',
        editable: true,
        isNote: true,
      }] : [{
        k: 'LICA Notes',
        v: '—',
        c: 'high',
        pct: null,
        col: 'lica_notes',
        editable: true,
        isNote: true,
      }]),
    ];

    res.json({
      ...row,
      base64_pdf,
      file_mime,
      id:                  row.file_id || String(row.id),
      doc_id:              row.file_id || String(row.id),
      vendor_customer_name: row.nama_perusahaan || row.customer || '—',
      fields,
    });
  } catch (e) {
    console.error('❌ /review error:', e.message, e.stack);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/documents/:id/approve
// :id = file_id (text) atau id (int)
app.post('/api/documents/:id/approve', requireAuth, async (req, res) => {
  const reviewer = req.user.full_name || req.body.reviewed_by || 'unknown';
  const { id } = req.params;
  try {
    // Resolve ocr_id dan file_id
    let resolvedFileId = id;
    let resolvedOcrId  = null;
    if (/^\d+$/.test(id)) {
      const ocrRef = await q(
        `SELECT id, file_id FROM istana_surya.document_ocr_detail WHERE id = $1 LIMIT 1`,
        [parseInt(id)]
      );
      if (ocrRef.rows.length) {
        resolvedOcrId  = ocrRef.rows[0].id;
        resolvedFileId = ocrRef.rows[0].file_id;
      }
    }

    // Waktu Jakarta (UTC+7)
    const jakartaNow = `NOW() AT TIME ZONE 'Asia/Jakarta'`;

    // 1. Update status di document_ocr_detail — tepat per ocr_id (independen per baris)
    let approveResult;
    if (resolvedOcrId) {
      approveResult = await q(`
        UPDATE istana_surya.document_ocr_detail
        SET status = 'approved',
            updated_at = (${jakartaNow})::TEXT
        WHERE id = $1
        RETURNING file_id, status
      `, [resolvedOcrId]);
    } else {
      // Fallback: update semua baris dengan file_id ini
      approveResult = await q(`
        UPDATE istana_surya.document_ocr_detail
        SET status = 'approved',
            updated_at = (${jakartaNow})::TEXT
        WHERE file_id = $1
        RETURNING file_id, status
      `, [resolvedFileId]);
    }
    if (!approveResult.rows.length) return res.status(404).json({ error: 'Document not found' });

    // 2. Sync upload_documents.status: approved jika SEMUA baris OCR untuk file_id ini sudah approved
    const remaining = await q(`
      SELECT COUNT(*) AS cnt FROM istana_surya.document_ocr_detail
      WHERE file_id = $1 AND status NOT IN ('approved','successfully_sent_to_sap_b1')
    `, [resolvedFileId]);
    if (parseInt(remaining.rows[0].cnt) === 0) {
      await q(`
        UPDATE istana_surya.upload_documents SET status = 'approved', updated_at = (${jakartaNow})::TEXT
        WHERE file_id = $1
      `, [resolvedFileId]);
    }

    const result = { rows: approveResult.rows };

    res.json({
      ok: true,
      status: 'approved',
      reviewed_by: reviewer,
      file_id: approveResult.rows[0].file_id,
      approved_at: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/documents/:id/send-sap
app.post('/api/documents/:id/send-sap', requireAuth, async (req, res) => {
  const { success, sap_entry } = req.body;
  const { id } = req.params;
  const newStatus = success !== false ? 'successfully_sent_to_sap_b1' : 'failed_sent_to_sap_b1';
  try {
    let sapFileId = id;
    if (/^\d+$/.test(id)) {
      const ocrRef = await q(`SELECT file_id FROM istana_surya.document_ocr_detail WHERE id = $1 LIMIT 1`, [parseInt(id)]);
      if (ocrRef.rows.length) sapFileId = ocrRef.rows[0].file_id;
    }
    // Update dod.status per ocr_id jika tersedia, else by file_id
    if (/^\d+$/.test(String(id))) {
      await q(`UPDATE istana_surya.document_ocr_detail SET status = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE id = $2`,
        [newStatus, parseInt(id)]);
    } else {
      await q(`UPDATE istana_surya.document_ocr_detail SET status = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $2`,
        [newStatus, sapFileId]);
    }
    const result = await q(`
      UPDATE istana_surya.upload_documents
      SET status = $2, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT
      WHERE file_id = $1 OR id::TEXT = $1
      RETURNING file_id, status
    `, [sapFileId, newStatus]);
    if (!result.rows.length) return res.status(404).json({ error: 'Document not found' });
    res.json({ ok: true, status: newStatus });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/documents/:id/field-edit
// Mengupdate kolom di document_ocr_detail berdasarkan field_col
app.post('/api/documents/:id/field-edit', requireAuth, async (req, res) => {
  const { field_col, new_value } = req.body;
  const editor = req.user.full_name || 'unknown';
  const { id } = req.params;

  // Whitelist kolom yang boleh diedit (cegah SQL injection via column name)
  const ALLOWED_COLS = [
    'nama_perusahaan', 'tipe', 'tanggal_dokumen', 'customer',
    'alamat', 'so_number', 'subtotal', 'lica_notes',
    'nama_item', 'total_item', 'harga_per_item', 'no_po_ref',
  ];
  if (!ALLOWED_COLS.includes(field_col)) {
    return res.status(400).json({ error: `Column '${field_col}' is not editable via this endpoint.` });
  }

  try {
    // ── Sanitasi new_value untuk kolom numerik ──
    const NUMERIC_COLS = ['subtotal', 'harga_per_item', 'total_item'];
    let sanitized_value = new_value;
    if (NUMERIC_COLS.includes(field_col)) {
      const cleaned = String(new_value).replace(/[Rp\s]/gi, '').replace(/\./g, '').replace(/,/g, '.').trim();
      const parsed  = parseFloat(cleaned);
      if (isNaN(parsed)) return res.status(400).json({ error: `Nilai '${new_value}' tidak valid untuk kolom ${field_col}` });
      sanitized_value = parsed;
    }

    // id bisa berupa ocr_id (integer) atau file_id (text)
    // Kalau angka → treat sebagai ocr_id (document_ocr_detail.id) → update tepat 1 baris
    let ocrId = null;
    let file_id = null;
    if (/^\d+$/.test(String(id))) {
      const ocrRef = await q(`SELECT id, file_id FROM istana_surya.document_ocr_detail WHERE id = $1 LIMIT 1`, [parseInt(id)]);
      if (!ocrRef.rows.length) return res.status(404).json({ error: 'OCR record not found' });
      ocrId   = ocrRef.rows[0].id;
      file_id = ocrRef.rows[0].file_id;
    } else {
      // Fallback: cari by file_id di upload_documents
      const ref = await q(`SELECT file_id FROM istana_surya.upload_documents WHERE file_id = $1 LIMIT 1`, [id]);
      if (!ref.rows.length) return res.status(404).json({ error: 'Document not found' });
      file_id = ref.rows[0].file_id;
    }

    // Update hanya 1 baris OCR yang tepat
    if (ocrId) {
      await q(
        `UPDATE istana_surya.document_ocr_detail SET ${field_col} = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE id = $2`,
        [sanitized_value, ocrId]
      );
    } else {
      await q(
        `UPDATE istana_surya.document_ocr_detail SET ${field_col} = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $2`,
        [sanitized_value, file_id]
      );
    }
    await q(`UPDATE istana_surya.upload_documents SET updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $1`, [file_id]);

    res.json({ ok: true, field_col, new_value: sanitized_value, edited_by: editor });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
//  WEBHOOK — dipanggil oleh workflow Yitshak (n8n) setelah OCR selesai
//  POST /api/webhook/ocr-result
//  Body: { file_id, total_confidence, akurasi_po_header, akurasi_item, ... semua kolom OCR }
// ════════════════════════════════════════════════════════════
app.post('/api/webhook/ocr-result', async (req, res) => {
  // Tidak butuh auth — dipanggil internal dari n8n
  const body = req.body;
  const { file_id } = body;
  if (!file_id) return res.status(400).json({ error: 'file_id required' });

  try {
    // Ambil atau hitung total_confidence
    const totalConf = parseFloat(body.total_confidence ?? 0);

    // Threshold: >= 90 → menunggu_review, < 90 → antrian_manual
    const newStatus = totalConf >= 90 ? 'menunggu_review' : 'antrian_manual';

    // Upsert ke document_ocr_detail
    const UPSERT_COLS = [
      'base64_pdf','akurasi_po_header','akurasi_item',
      'nama_perusahaan','akurasi_nama_perusahaan',
      'tipe','akurasi_tipe',
      'tanggal_dokumen','akurasi_tanggal',
      'customer','akurasi_customer',
      'alamat','akurasi_alamat',
      'nama_item','akurasi_nama_item',
      'total_item','akurasi_total_item',
      'harga_per_item','akurasi_harga_per_item',
      'subtotal','akurasi_subtotal',
      'so_number','akurasi_no_po_ref',
    ];

    const setClauses = UPSERT_COLS
      .filter(col => body[col] !== undefined)
      .map((col, i) => `${col} = $${i + 2}`)
      .join(', ');
    const setValues = UPSERT_COLS
      .filter(col => body[col] !== undefined)
      .map(col => body[col]);

    if (setClauses) {
      // Cek apakah sudah ada record OCR untuk file_id ini
      const existing = await q(
        `SELECT id FROM istana_surya.document_ocr_detail WHERE file_id = $1`, [file_id]
      );
      if (existing.rows.length) {
        await q(
          `UPDATE istana_surya.document_ocr_detail SET ${setClauses}, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $1`,
          [file_id, ...setValues]
        );
      } else {
        const insertCols = ['file_id', ...UPSERT_COLS.filter(col => body[col] !== undefined)];
        const insertPlaceholders = insertCols.map((_, i) => `$${i + 1}`).join(', ');
        await q(
          `INSERT INTO istana_surya.document_ocr_detail(${insertCols.join(', ')}) VALUES(${insertPlaceholders})`,
          [file_id, ...setValues]
        );
      }
    }

    // Update status di document_ocr_detail (per file_id — webhook tidak tahu ocr_id spesifik)
    await q(
      `UPDATE istana_surya.document_ocr_detail SET status = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $2`,
      [newStatus, file_id]
    );
    // Sync ke upload_documents juga
    await q(
      `UPDATE istana_surya.upload_documents SET status = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Jakarta')::TEXT WHERE file_id = $2`,
      [newStatus, file_id]
    );

    res.json({ ok: true, file_id, status: newStatus, total_confidence: totalConf });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
//  UPLOAD BATCHES
//  Batch = kumpulan insert ke istana_surya.upload_documents sekaligus
// ════════════════════════════════════════════════════════════

// POST /api/upload/batch  — insert file-file ke upload_documents, return list file_id
app.post('/api/upload/batch', requireAuth, async (req, res) => {
  const { filenames } = req.body;
  if (!filenames?.length) return res.status(400).json({ error: 'filenames required' });
  const uploader = req.user.full_name || 'admin';
  try {
    const inserted = [];
    for (const fname of filenames) {
      const file_id = require('crypto').randomUUID();
      await q(
        `INSERT INTO istana_surya.upload_documents(file_id, nama_doc, status, uploaded_by)
         VALUES ($1, $2, 'on_progres', $3)`,
        [file_id, fname, uploader]
      );
      inserted.push({ file_id, filename: fname });
    }
    res.json({ batch_id: `batch_${Date.now()}`, files: inserted });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/upload/orphans — hapus row di upload_documents yang tidak punya OCR data
// Dipanggil manual untuk cleanup duplikat/ghost uploads
app.delete('/api/upload/orphans', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await q(`
      DELETE FROM istana_surya.upload_documents
      WHERE file_id NOT IN (
        SELECT file_id FROM istana_surya.document_ocr_detail
      )
      RETURNING file_id, nama_doc, status
    `);
    res.json({
      ok: true,
      deleted: result.rows.length,
      rows: result.rows,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/upload/batch/:id — tidak relevan lagi (batch sekarang langsung insert)
//   Endpoint ini dipertahankan agar tidak 404, tapi return kosong
app.get('/api/upload/batch/:id', requireAuth, async (req, res) => {
  res.json({ batch_id: req.params.id, note: 'Batch tracking tidak dipakai di arsitektur baru.' });
});

// ════════════════════════════════════════════════════════════
//  START SERVER
// ════════════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 LICA API running at http://localhost:${PORT}`);
  console.log(`   DB: ${useSSL ? "public proxy" : "private network"}`);
});