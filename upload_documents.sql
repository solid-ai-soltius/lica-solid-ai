-- ============================================================
--  LICA — Upload Dokumen Table
--  Schema  : skl
--  Version : 1.0
-- ============================================================

SET search_path TO skl;

-- ── DROP jika sudah ada ─────────────────────────────────────
DROP TABLE IF EXISTS skl.upload_documents CASCADE;

-- ============================================================
--  TABLE: upload_documents
--
--  Diisi saat user klik "Kirim ke LICA".
--  Status diupdate oleh workflow Yitshak setelah OCR selesai.
-- ============================================================

CREATE TABLE skl.upload_documents (

  id          SERIAL        PRIMARY KEY,         -- auto increment 1, 2, 3 ...
  file_id     TEXT          NOT NULL UNIQUE,      -- unique ID per file (bisa UUID dari n8n)
  nama_doc    TEXT          NOT NULL,             -- nama file asli (original_filename)
  status      TEXT          NOT NULL DEFAULT NULL,-- NULL saat upload, diisi Yitshak setelah proses
  uploaded_by TEXT,                               -- nama user yang upload
  uploaded_at TEXT,
  updated_at  TEXT

);

ALTER TABLE skl.upload_documents
  ALTER COLUMN status DROP NOT NULL;             -- status boleh NULL di awal

CREATE INDEX idx_upload_docs_file_id    ON skl.upload_documents(file_id);
CREATE INDEX idx_upload_docs_status     ON skl.upload_documents(status);
CREATE INDEX idx_upload_docs_batch      ON skl.upload_documents(batch_id);
CREATE INDEX idx_upload_docs_uploaded   ON skl.upload_documents(uploaded_at DESC);

-- ── Trigger updated_at ─────────────────────────────────────
CREATE OR REPLACE FUNCTION skl.trg_upload_docs_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER tg_upload_docs_updated_at
  BEFORE UPDATE ON skl.upload_documents
  FOR EACH ROW EXECUTE FUNCTION skl.trg_upload_docs_updated_at();


-- ============================================================
--  VIEW: v_upload_documents
--  Yang ditampilkan di menu Upload Dokumen
-- ============================================================
CREATE OR REPLACE VIEW skl.v_upload_documents AS
SELECT
  id,
  file_id,
  nama_doc,
  status,
  document_id,
  uploaded_by,
  uploaded_at,
  updated_at
FROM skl.upload_documents
ORDER BY uploaded_at DESC;


-- ============================================================
--  Query referensi untuk n8n Yitshak
-- ============================================================

-- INSERT saat user upload (dipanggil dari server.js / n8n):
-- INSERT INTO skl.upload_documents(file_id, nama_doc, uploaded_by, batch_id)
-- VALUES ('uuid-xxx', 'PO-2026-0041.pdf', 'Tyarani Puspa', 1);

-- UPDATE status setelah OCR selesai (dipanggil workflow Yitshak):
-- UPDATE skl.upload_documents
-- SET status = 'done', document_id = 'PO-2026-0041'
-- WHERE file_id = 'uuid-xxx';

-- Nilai status yang valid:
-- NULL          → baru diupload, belum diproses
-- 'processing'  → sedang di-OCR
-- 'done'        → OCR selesai, sudah masuk tabel documents
-- 'failed'      → gagal OCR

-- Cek progress batch:
-- SELECT
--   COUNT(*)                              AS total,
--   COUNT(*) FILTER (WHERE status = 'done')   AS selesai,
--   COUNT(*) FILTER (WHERE status IS NULL)    AS belum,
--   COUNT(*) FILTER (WHERE status = 'failed') AS gagal
-- FROM skl.upload_documents
-- WHERE batch_id = 1;