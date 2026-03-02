const crypto = require('node:crypto');

function normalizePath(value) {
  return String(value || '')
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '')
    .replace(/\/{2,}/g, '/');
}

function normalizePrivateKey(value) {
  if (!value) return '';
  return String(value).replace(/\\n/g, '\n').trim();
}

function normalizeToken(value) {
  if (!value) return '';
  return String(value).replace(/^Bearer\s+/i, '').trim();
}

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function escapeDriveQueryValue(value) {
  return String(value || '').replace(/'/g, "\\'");
}

async function parseGoogleError(response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const json = await response.json().catch(() => ({}));
    if (json?.error?.message) return json.error.message;
    if (json?.error_description) return json.error_description;
    if (json?.message) return json.message;
    return JSON.stringify(json);
  }
  return response.text().catch(() => '');
}

class GoogleDriveStorageAdapter {
  constructor(config) {
    this.type = 'gdrive';
    this.config = {
      folderId: String(config.folderId || '').trim(),
      prefix: normalizePath(config.prefix || config.path || config.rootPath),
      accessToken: normalizeToken(config.accessToken || config.token),
      serviceAccountEmail: String(config.serviceAccountEmail || config.clientEmail || '').trim(),
      privateKey: normalizePrivateKey(config.privateKey),
      tokenUri: String(config.tokenUri || 'https://oauth2.googleapis.com/token').trim(),
      scope: 'https://www.googleapis.com/auth/drive',
    };

    this.cachedToken = null;
  }

  validate() {
    if (!this.config.folderId) {
      throw new Error('Google Drive storage requires folderId (share a folder to service account).');
    }

    const hasServiceAccount = Boolean(this.config.serviceAccountEmail && this.config.privateKey);
    if (!this.config.accessToken && !hasServiceAccount) {
      throw new Error('Google Drive storage requires accessToken, or serviceAccountEmail + privateKey.');
    }
  }

  async getAccessToken() {
    if (this.config.accessToken) {
      return this.config.accessToken;
    }

    const now = Math.floor(Date.now() / 1000);
    if (this.cachedToken?.token && this.cachedToken.expiresAt > now + 60) {
      return this.cachedToken.token;
    }

    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iss: this.config.serviceAccountEmail,
      scope: this.config.scope,
      aud: this.config.tokenUri,
      exp: now + 3600,
      iat: now,
    };

    const encodedHeader = base64url(JSON.stringify(header));
    const encodedPayload = base64url(JSON.stringify(payload));
    const unsigned = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto
      .createSign('RSA-SHA256')
      .update(unsigned)
      .sign(this.config.privateKey, 'base64url');

    const assertion = `${unsigned}.${signature}`;
    const tokenBody = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    });

    const response = await fetch(this.config.tokenUri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenBody.toString(),
    });

    const json = await response.json().catch(() => ({}));
    if (!response.ok || !json.access_token) {
      throw new Error(json.error_description || json.error || `Google token exchange failed (${response.status}).`);
    }

    this.cachedToken = {
      token: json.access_token,
      expiresAt: now + Number(json.expires_in || 3600),
    };

    return this.cachedToken.token;
  }

  async authHeaders(extra = {}) {
    const token = await this.getAccessToken();
    return {
      Authorization: `Bearer ${token}`,
      ...extra,
    };
  }

  driveApi(pathname) {
    return `https://www.googleapis.com/drive/v3${pathname}`;
  }

  uploadApi() {
    return 'https://www.googleapis.com/upload/drive/v3/files';
  }

  resolveDisplayName(storageKey = '', fileName = '') {
    const normalized = normalizePath(storageKey || fileName || `file_${Date.now()}`);
    const withPrefix = this.config.prefix ? `${this.config.prefix}/${normalized}` : normalized;
    return withPrefix.replace(/\//g, '__');
  }

  async getFileById(fileId) {
    const url = new URL(this.driveApi(`/files/${encodeURIComponent(fileId)}`));
    url.searchParams.set('supportsAllDrives', 'true');
    url.searchParams.set('fields', 'id,name,mimeType,size,parents');

    const response = await fetch(url.toString(), {
      headers: await this.authHeaders(),
    });

    if (response.status === 404) return null;
    if (!response.ok) {
      const detail = await parseGoogleError(response);
      throw new Error(`Google Drive file lookup failed (${response.status}): ${detail}`);
    }

    return response.json();
  }

  async findFileByStorageKey(storageKey) {
    const queryParts = [
      "trashed = false",
      `appProperties has { key='kvStorageKey' and value='${escapeDriveQueryValue(storageKey)}' }`,
      `'${escapeDriveQueryValue(this.config.folderId)}' in parents`,
    ];

    const url = new URL(this.driveApi('/files'));
    url.searchParams.set('q', queryParts.join(' and '));
    url.searchParams.set('supportsAllDrives', 'true');
    url.searchParams.set('includeItemsFromAllDrives', 'true');
    url.searchParams.set('pageSize', '5');
    url.searchParams.set('orderBy', 'modifiedTime desc');
    url.searchParams.set('fields', 'files(id,name,mimeType,size,modifiedTime)');

    const response = await fetch(url.toString(), {
      headers: await this.authHeaders(),
    });

    if (!response.ok) {
      const detail = await parseGoogleError(response);
      throw new Error(`Google Drive search failed (${response.status}): ${detail}`);
    }

    const json = await response.json().catch(() => ({}));
    return json.files?.[0] || null;
  }

  async resolveFile({ storageKey, metadata = {} }) {
    if (metadata.gdriveFileId) {
      const byId = await this.getFileById(metadata.gdriveFileId);
      if (byId) return byId;
    }

    if (!storageKey) return null;
    return this.findFileByStorageKey(storageKey);
  }

  async testConnection() {
    this.validate();

    const url = new URL(this.driveApi(`/files/${encodeURIComponent(this.config.folderId)}`));
    url.searchParams.set('supportsAllDrives', 'true');
    url.searchParams.set('fields', 'id,name,mimeType');

    const response = await fetch(url.toString(), {
      headers: await this.authHeaders(),
    });

    if (!response.ok) {
      const detail = await parseGoogleError(response);
      return {
        connected: false,
        status: response.status,
        detail: detail || 'Cannot access target Google Drive folder.',
      };
    }

    const json = await response.json().catch(() => ({}));
    return {
      connected: true,
      status: response.status,
      folder: json.name || this.config.folderId,
      authMode: this.config.accessToken ? 'access_token' : 'service_account',
    };
  }

  async upload({ storageKey, buffer, mimeType, fileName }) {
    this.validate();

    if (!storageKey) {
      throw new Error('Google Drive upload requires storageKey.');
    }

    // Upsert behavior: remove old file for same storageKey to keep one-to-one mapping.
    const existing = await this.findFileByStorageKey(storageKey);
    if (existing?.id) {
      await this.delete({ storageKey, metadata: { gdriveFileId: existing.id } });
    }

    const metadata = {
      name: this.resolveDisplayName(storageKey, fileName),
      parents: [this.config.folderId],
      appProperties: {
        kvStorageKey: String(storageKey),
        kvAdapter: 'k-vault-gdrive',
      },
    };

    const boundary = `kvault_gdrive_${Date.now().toString(16)}`;
    const prelude = [
      `--${boundary}`,
      'Content-Type: application/json; charset=UTF-8',
      '',
      JSON.stringify(metadata),
      `--${boundary}`,
      `Content-Type: ${mimeType || 'application/octet-stream'}`,
      '',
    ].join('\r\n');
    const epilogue = `\r\n--${boundary}--`;

    const body = Buffer.concat([
      Buffer.from(prelude, 'utf8'),
      Buffer.from(buffer),
      Buffer.from(epilogue, 'utf8'),
    ]);

    const url = new URL(this.uploadApi());
    url.searchParams.set('uploadType', 'multipart');
    url.searchParams.set('supportsAllDrives', 'true');
    url.searchParams.set('fields', 'id,name,mimeType,size,webViewLink');

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: await this.authHeaders({
        'Content-Type': `multipart/related; boundary=${boundary}`,
        'Content-Length': String(body.byteLength),
      }),
      body,
    });

    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(
        `Google Drive upload failed (${response.status}): ${json?.error?.message || json.message || 'Unknown error'}`
      );
    }

    return {
      storageKey,
      metadata: {
        gdriveFileId: json.id || null,
        gdriveName: json.name || null,
      },
    };
  }

  async download({ storageKey, metadata = {}, range }) {
    this.validate();

    const file = await this.resolveFile({ storageKey, metadata });
    if (!file?.id) return null;

    const url = new URL(this.driveApi(`/files/${encodeURIComponent(file.id)}`));
    url.searchParams.set('alt', 'media');
    url.searchParams.set('supportsAllDrives', 'true');

    const headers = {};
    if (range) headers.Range = range;

    const response = await fetch(url.toString(), {
      headers: await this.authHeaders(headers),
    });

    if (!response.ok && response.status !== 206) {
      if (response.status === 404) return null;
      const detail = await parseGoogleError(response);
      throw new Error(`Google Drive download failed (${response.status}): ${detail}`);
    }

    return response;
  }

  async delete({ storageKey, metadata = {} }) {
    this.validate();

    const file = await this.resolveFile({ storageKey, metadata });
    if (!file?.id) return true;

    const url = new URL(this.driveApi(`/files/${encodeURIComponent(file.id)}`));
    url.searchParams.set('supportsAllDrives', 'true');

    const response = await fetch(url.toString(), {
      method: 'DELETE',
      headers: await this.authHeaders(),
    });

    if (response.ok || response.status === 404) return true;
    const detail = await parseGoogleError(response);
    throw new Error(`Google Drive delete failed (${response.status}): ${detail}`);
  }
}

module.exports = {
  GoogleDriveStorageAdapter,
};
