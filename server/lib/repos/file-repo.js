const { all, get, run } = require('../../db');

function parseExtra(extraJson) {
  try {
    return JSON.parse(extraJson || '{}');
  } catch {
    return {};
  }
}

function toMetadata(row) {
  const extra = parseExtra(row.extra_json);
  return {
    TimeStamp: row.created_at,
    ListType: row.list_type || 'None',
    Label: row.label || 'None',
    liked: Boolean(row.liked),
    fileName: row.file_name,
    fileSize: row.file_size || 0,
    storageType: row.storage_type,
    storageConfigId: row.storage_config_id,
    mimeType: row.mime_type || '',
    ...extra,
  };
}

function mapRow(row) {
  return {
    name: row.id,
    metadata: toMetadata(row),
  };
}

class FileRepository {
  constructor(db) {
    this.db = db;
  }

  create(file) {
    const now = Date.now();
    run(
      this.db,
      `INSERT INTO files(
        id, storage_config_id, storage_type, storage_key, file_name,
        file_size, mime_type, list_type, label, liked, extra_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        file.id,
        file.storageConfigId,
        file.storageType,
        file.storageKey,
        file.fileName,
        file.fileSize || 0,
        file.mimeType || 'application/octet-stream',
        file.listType || 'None',
        file.label || 'None',
        file.liked ? 1 : 0,
        JSON.stringify(file.extra || {}),
        now,
        now,
      ]
    );

    return this.getById(file.id);
  }

  getById(id) {
    const row = get(this.db, 'SELECT * FROM files WHERE id = ?', [id]);
    if (!row) return null;
    return {
      ...row,
      metadata: toMetadata(row),
    };
  }

  updateMetadata(id, patch) {
    const current = this.getById(id);
    if (!current) return null;

    const nextExtra = { ...parseExtra(current.extra_json), ...(patch.extra || {}) };

    run(
      this.db,
      `UPDATE files
       SET file_name = ?,
           list_type = ?,
           label = ?,
           liked = ?,
           extra_json = ?,
           updated_at = ?
       WHERE id = ?`,
      [
        patch.fileName || current.file_name,
        patch.listType || current.list_type,
        patch.label || current.label,
        patch.liked != null ? (patch.liked ? 1 : 0) : current.liked,
        JSON.stringify(nextExtra),
        Date.now(),
        id,
      ]
    );

    return this.getById(id);
  }

  delete(id) {
    const result = run(this.db, 'DELETE FROM files WHERE id = ?', [id]);
    return Number(result.changes || 0) > 0;
  }

  count(filters = {}) {
    const { whereClause, params } = this.buildWhere(filters);
    const row = get(this.db, `SELECT COUNT(1) AS c FROM files ${whereClause}`, params);
    return Number(row?.c || 0);
  }

  list({
    limit = 100,
    cursor,
    filters = {},
    includeStats = false,
  } = {}) {
    const normalizedLimit = Math.max(1, Math.min(1000, Number(limit) || 100));
    const offset = Math.max(0, Number(cursor) || 0);

    const { whereClause, params } = this.buildWhere(filters);

    const rows = all(
      this.db,
      `SELECT * FROM files ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, normalizedLimit, offset]
    );

    const total = this.count(filters);
    const nextOffset = offset + rows.length;

    const payload = {
      keys: rows.map(mapRow),
      list_complete: nextOffset >= total,
      cursor: nextOffset >= total ? null : String(nextOffset),
      pageCount: rows.length,
    };

    if (includeStats) {
      payload.stats = this.buildStats(filters);
    }

    return payload;
  }

  buildStats(filters = {}) {
    const { whereClause, params } = this.buildWhere(filters);
    const rows = all(this.db, `SELECT storage_type, file_name FROM files ${whereClause}`, params);

    const byType = { image: 0, video: 0, audio: 0, document: 0 };
    const byStorage = {
      telegram: 0,
      r2: 0,
      s3: 0,
      discord: 0,
      huggingface: 0,
      webdav: 0,
      github: 0,
      gdrive: 0,
      onedrive: 0,
    };

    rows.forEach((row) => {
      const ext = String(row.file_name || '').split('.').pop().toLowerCase();
      const type = inferFileType(ext);
      byType[type] += 1;
      if (Object.prototype.hasOwnProperty.call(byStorage, row.storage_type)) {
        byStorage[row.storage_type] += 1;
      }
    });

    return {
      total: rows.length,
      byType,
      byStorage,
    };
  }

  buildWhere(filters = {}) {
    const clauses = [];
    const params = [];

    if (filters.search) {
      clauses.push('(LOWER(file_name) LIKE ? OR LOWER(id) LIKE ?)');
      const term = `%${String(filters.search).toLowerCase()}%`;
      params.push(term, term);
    }

    if (filters.storageType && filters.storageType !== 'all') {
      clauses.push('storage_type = ?');
      params.push(String(filters.storageType));
    }

    if (filters.listType && filters.listType !== 'all') {
      clauses.push('list_type = ?');
      params.push(String(filters.listType));
    }

    return {
      whereClause: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
      params,
    };
  }
}

function inferFileType(ext) {
  const image = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'ico', 'svg', 'heic', 'heif', 'avif']);
  const video = new Set(['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'm4v', '3gp', 'ts']);
  const audio = new Set(['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma', 'ape', 'opus']);

  if (image.has(ext)) return 'image';
  if (video.has(ext)) return 'video';
  if (audio.has(ext)) return 'audio';
  return 'document';
}

module.exports = {
  FileRepository,
  inferFileType,
};
