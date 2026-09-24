SET search_path TO skl;

-- ── DROP jika sudah ada (re-run safe) ──────────────────────
DROP TABLE IF EXISTS skl.document_ocr_detail CASCADE;

-- ============================================================
--  TABLE: document_ocr_detail
--
--  Satu baris = satu PO/SO yang sudah di-OCR oleh LICA.
--  Setiap field punya kolom nilai (extracted) + akurasi (0-100).
--
--  Kolom akurasi:
--    - akurasi_po_header   : confidence hasil OCR header PO secara keseluruhan
--    - akurasi_item        : confidence hasil OCR baris-baris item (rata2)
--    - total_confidence    : (akurasi_po_header + akurasi_item) / 2
--
--  Field-level accuracy per kolom utama:
--    nama_perusahaan, tipe, tanggal_dokumen, customer,
--    alamat, nama_item, total_item, harga_per_item,
--    subtotal, no_po_ref
-- ============================================================

CREATE TABLE skl.document_ocr_detail (

  -- ── Primary key & FK ──────────────────────────────────────
  id                        SERIAL          PRIMARY KEY,
  file_id               TEXT            NOT NULL,

  -- ── Raw PDF ───────────────────────────────────────────────
  base64_pdf                TEXT,           -- base64-encoded PDF untuk preview di browser
  so_number                 TEXT,
  
  -- ── Confidence keseluruhan ────────────────────────────────
  akurasi_po_header         NUMERIC(5,2),   -- 0.00 – 100.00  | OCR confidence header PO
  akurasi_item              NUMERIC(5,2),   -- 0.00 – 100.00  | OCR confidence baris item (avg)
  total_confidence          NUMERIC(5,2),    -- (akurasi_po_header + akurasi_item) / 2
   

  -- ── Nama Perusahaan ───────────────────────────────────────
  nama_perusahaan           TEXT,
  akurasi_nama_perusahaan   NUMERIC(5,2),

  -- ── Tipe Dokumen ──────────────────────────────────────────
  tipe                      TEXT,           -- 'PO' | 'SO'
  akurasi_tipe              NUMERIC(5,2),

  -- ── Tanggal Dokumen ───────────────────────────────────────
  tanggal_dokumen           DATE,           -- tanggal yg tertera di dalam PDF
  akurasi_tanggal           NUMERIC(5,2),

  -- ── Customer ──────────────────────────────────────────────
  customer                  TEXT,
  akurasi_customer          NUMERIC(5,2),

  -- ── Alamat ────────────────────────────────────────────────
  alamat                    TEXT,
  akurasi_alamat            NUMERIC(5,2),

  -- ── Nama Item (bisa multi-item, disimpan sebagai JSONB) ───
  -- Format: ["Baut M10 x 30mm", "Mur M10", ...]
  nama_item                 TEXT,
  akurasi_nama_item         NUMERIC(5,2),   -- rata-rata confidence semua nama item

  -- ── Total Item (jumlah qty per item) ─────────────────────
  -- Format: [50, 50, 30]
  total_item                INT4,
  akurasi_total_item        NUMERIC(5,2),

  -- ── Harga Per Item ────────────────────────────────────────
  -- Format: [85000, 45000, 38000]
  harga_per_item            INT8,
  akurasi_harga_per_item    NUMERIC(5,2),

  -- ── Subtotal ──────────────────────────────────────────────
  subtotal                  NUMERIC(20,2),  -- grand total dokumen
  akurasi_subtotal          NUMERIC(5,2),

  -- ── No. PO Ref ────────────────────────────────────────────
  no_po_ref                 TEXT,
  akurasi_no_po_ref         NUMERIC(5,2),

  LICA_notes                     TEXT,

  -- ── Metadata ──────────────────────────────────────────────
  processed_at              TEXT,
  updated_at                TEXT     

);

-- ── Constraint ─────────────────────────────────────────────
ALTER TABLE skl.document_ocr_detail
  ADD CONSTRAINT uq_ocr_detail_document UNIQUE (document_id);
  -- 1 dokumen = 1 baris OCR detail

-- ── Index ──────────────────────────────────────────────────
CREATE INDEX idx_ocr_detail_document_id   ON skl.document_ocr_detail(document_id);
CREATE INDEX idx_ocr_detail_confidence    ON skl.document_ocr_detail(total_confidence);
CREATE INDEX idx_ocr_detail_processed_at  ON skl.document_ocr_detail(processed_at DESC);

-- ── Trigger: auto-update updated_at ────────────────────────
CREATE OR REPLACE FUNCTION skl.trg_ocr_detail_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER tg_ocr_detail_updated_at
  BEFORE UPDATE ON skl.document_ocr_detail
  FOR EACH ROW EXECUTE FUNCTION skl.trg_ocr_detail_updated_at();

-- ── Trigger: sync total_confidence ke tabel documents ──────
-- Ketika OCR detail diinsert/update, update juga ocr_confidence_score
-- di tabel documents (pakai total_confidence)
CREATE OR REPLACE FUNCTION skl.trg_sync_confidence_to_documents()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  UPDATE skl.document_metadata
  SET
    ocr_confidence_score = NEW.total_confidence,
    -- Tentukan status berdasarkan threshold 95%
    status = CASE
      WHEN NEW.total_confidence >= 95 THEN 'menunggu_review'::skl.doc_status
      ELSE 'antrian_manual'::skl.doc_status
    END,
    -- Sync field-field utama ke tabel documents
    company_name          = COALESCE(NEW.nama_perusahaan,    company_name),
    document_date         = COALESCE(NEW.tanggal_dokumen,    document_date),
    vendor_customer_name  = COALESCE(NEW.customer,           vendor_customer_name),
    address               = COALESCE(NEW.alamat,             address),
    total_value           = COALESCE(NEW.subtotal,           total_value),
    po_reference_number   = COALESCE(NEW.no_po_ref,          po_reference_number),
    updated_at            = NOW()
  WHERE id = NEW.document_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER tg_sync_confidence_to_documents
  AFTER INSERT OR UPDATE ON skl.document_ocr_detail
  FOR EACH ROW EXECUTE FUNCTION skl.trg_sync_confidence_to_documents();


-- ============================================================
--  VIEW: v_review_detail  (update — pakai document_ocr_detail)
-- ============================================================
CREATE OR REPLACE VIEW skl.v_review_detail AS
SELECT
  d.id                              AS doc_id,
  d.status,
  d.file_path,
  d.ingest_date,
  d.updated_at,

  -- dari document_ocr_detail
  o.base64_pdf,
  o.akurasi_po_header               AS akurasi,
  o.akurasi_item,
  o.total_confidence,

  o.nama_perusahaan,
  o.akurasi_nama_perusahaan,

  d.document_type                   AS tipe,
  o.akurasi_tipe,

  o.tanggal_dokumen,
  o.akurasi_tanggal,

  o.customer,
  o.akurasi_customer,

  o.alamat,
  o.akurasi_alamat,

  o.nama_item,
  o.akurasi_nama_item,

  o.total_item,
  o.akurasi_total_item,

  o.harga_per_item,
  o.akurasi_harga_per_item,

  o.subtotal,
  o.akurasi_subtotal,

  o.no_po_ref,
  o.akurasi_no_po_ref,

  o.ocr_engine,
  o.processed_at,

  -- Hitung berapa field low confidence (< 80%) untuk UI merah-putih
  (
    SELECT COUNT(*) FROM (
      VALUES
        (o.akurasi_nama_perusahaan),
        (o.akurasi_tipe),
        (o.akurasi_tanggal),
        (o.akurasi_customer),
        (o.akurasi_alamat),
        (o.akurasi_nama_item),
        (o.akurasi_total_item),
        (o.akurasi_harga_per_item),
        (o.akurasi_subtotal),
        (o.akurasi_no_po_ref)
    ) AS t(v)
    WHERE v < 80
  )                                 AS low_field_count,

  -- Total field yang punya nilai akurasi
  (
    SELECT COUNT(*) FROM (
      VALUES
        (o.akurasi_nama_perusahaan),
        (o.akurasi_tipe),
        (o.akurasi_tanggal),
        (o.akurasi_customer),
        (o.akurasi_alamat),
        (o.akurasi_nama_item),
        (o.akurasi_total_item),
        (o.akurasi_harga_per_item),
        (o.akurasi_subtotal),
        (o.akurasi_no_po_ref)
    ) AS t(v)
    WHERE v IS NOT NULL
  )                                 AS total_field_count

FROM skl.document_metadata d
LEFT JOIN skl.document_ocr_detail o ON o.document_id = d.id;


-- ============================================================
--  SAMPLE INSERT (untuk testing — diisi oleh workflow LICA)
-- ============================================================
/*
INSERT INTO skl.document_ocr_detail (
  document_id,
  base64_pdf,
  akurasi_po_header,
  akurasi_item,
  nama_perusahaan,         akurasi_nama_perusahaan,
  tipe,                    akurasi_tipe,
  tanggal_dokumen,         akurasi_tanggal,
  customer,                akurasi_customer,
  alamat,                  akurasi_alamat,
  nama_item,               akurasi_nama_item,
  total_item,              akurasi_total_item,
  harga_per_item,          akurasi_harga_per_item,
  subtotal,                akurasi_subtotal,
  no_po_ref,               akurasi_no_po_ref,
  ocr_engine
)
VALUES (
  'PO-2026-0041',
  NULL,                    -- base64 diisi oleh LICA
  97.5,                    -- akurasi header
  94.2,                    -- akurasi item
  'PT Sumber Jaya Utama',  98.1,
  'PO',                    99.0,
  '2026-05-05',            96.5,
  'CV Maju Teknik Mandiri',94.3,
  'Jl. Cempaka Putih Timur No. 12, Jakarta Pusat', 91.0,
  '["Baut M10 x 30mm Galvanis", "Mur M10 Galvanis", "Ring Pegas M10", "Baut Hex M12 x 50mm", "Kunci Ring 17-19mm"]',
  95.0,
  '[50, 50, 30, 20, 10]', 97.0,
  '[85000, 45000, 38000, 125000, 285000]', 96.5,
  7225000,                 98.0,
  'SO-2026-0115',          95.5,
  'google-vision'
);
*/

-- ── Query referensi ────────────────────────────────────────
-- Lihat review detail lengkap:
-- SELECT * FROM skl.v_review_detail WHERE doc_id = 'PO-2026-0041';

-- Lihat dokumen dengan confidence rendah:
-- SELECT doc_id, total_confidence, low_field_count
-- FROM skl.v_review_detail
-- WHERE total_confidence < 95
-- ORDER BY total_confidence ASC;

-- Update field setelah reviewer edit (via confirm_field_edit):
-- UPDATE skl.document_ocr_detail
-- SET customer = 'CV Maju Teknik Mandiri', akurasi_customer = 100
-- WHERE document_id = 'PO-2026-0041';