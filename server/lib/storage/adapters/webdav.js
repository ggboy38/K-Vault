function normalizeBaseUrl(raw) {
  if (!raw) return '';
  try {
    const url = new URL(String(raw));
    return url.toString().replace(/\/+$/, '');
  } catch {
    return '';
  }
}

function normalizeToken(value) {
  if (!value) return '';
  return String(value).replace(/^Bearer\s+/i, '').trim();
}

function normalizePath(value) {
  return String(value || '')
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '');
}

function splitPath(value) {
  const normalized = normalizePath(value);
  if (!normalized) return [];
  return normalized
    .split('/')
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function encodePathSegments(segments) {
  if (!segments.length) return '';
  return segments.map((segment) => encodeURIComponent(segment)).join('/');
}

function authMode(config) {
  if (config.bearerToken) return 'bearer';
  if (config.username && config.password) return 'basic';
  return 'none';
}

function decodeResponseTextSafe(response) {
  return response.text().catch(() => '');
}

class WebDAVStorageAdapter {
  constructor(config) {
    this.type = 'webdav';
    this.config = {
      baseUrl: normalizeBaseUrl(config.baseUrl),
      username: String(config.username || '').trim(),
      password: String(config.password || ''),
      bearerToken: normalizeToken(config.bearerToken || config.token),
      rootPath: normalizePath(config.rootPath),
    };
  }

  validate() {
    if (!this.config.baseUrl) {
      throw new Error('WebDAV storage requires a valid baseUrl.');
    }

    const mode = authMode(this.config);
    if (mode === 'none') {
      throw new Error('WebDAV storage requires username+password or bearerToken.');
    }
  }

  getAuthHeaders(extra = {}) {
    const headers = { ...extra };
    const mode = authMode(this.config);
    if (mode === 'bearer') {
      headers.Authorization = `Bearer ${this.config.bearerToken}`;
    } else if (mode === 'basic') {
      const token = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      headers.Authorization = `Basic ${token}`;
    }
    return headers;
  }

  buildSegments(storageKey = '') {
    return [...splitPath(this.config.rootPath), ...splitPath(storageKey)];
  }

  buildUrl(storageKey = '') {
    const relative = encodePathSegments(this.buildSegments(storageKey));
    return relative ? `${this.config.baseUrl}/${relative}` : this.config.baseUrl;
  }

  async fetchDav(method, storageKey = '', { headers = {}, body = null } = {}) {
    return fetch(this.buildUrl(storageKey), {
      method,
      headers: this.getAuthHeaders(headers),
      body,
    });
  }

  async testConnection() {
    this.validate();

    try {
      const optionsResponse = await this.fetchDav('OPTIONS', '', {
        headers: { Depth: '0' },
      });

      if (optionsResponse.ok) {
        return {
          connected: true,
          status: optionsResponse.status,
          method: 'OPTIONS',
        };
      }

      if (optionsResponse.status === 401 || optionsResponse.status === 403) {
        return {
          connected: false,
          status: optionsResponse.status,
          method: 'OPTIONS',
          detail: 'Authentication failed for WebDAV endpoint.',
        };
      }

      const propfindBody = [
        '<?xml version="1.0" encoding="utf-8" ?>',
        '<d:propfind xmlns:d="DAV:">',
        '  <d:prop><d:displayname /></d:prop>',
        '</d:propfind>',
      ].join('');

      const propfindResponse = await this.fetchDav('PROPFIND', '', {
        headers: {
          Depth: '0',
          'Content-Type': 'application/xml; charset=utf-8',
        },
        body: propfindBody,
      });

      const connected = propfindResponse.ok || propfindResponse.status === 207;
      const detail = connected ? '' : await decodeResponseTextSafe(propfindResponse);

      return {
        connected,
        status: propfindResponse.status,
        method: 'PROPFIND',
        detail: detail ? detail.slice(0, 500) : undefined,
      };
    } catch (error) {
      return {
        connected: false,
        detail: error.message || String(error),
      };
    }
  }

  async ensureCollectionPath(storageKey) {
    const rootSegments = splitPath(this.config.rootPath);
    const fileSegments = splitPath(storageKey);
    const directories = [...rootSegments, ...fileSegments.slice(0, -1)];
    if (directories.length === 0) return;

    for (let i = 0; i < directories.length; i += 1) {
      const absolutePath = encodePathSegments(directories.slice(0, i + 1));
      const response = await fetch(`${this.config.baseUrl}/${absolutePath}`, {
        method: 'MKCOL',
        headers: this.getAuthHeaders(),
      });

      // 201 created, 405 already exists, 301/302 redirected, 409 parent missing (should not happen here)
      if ([201, 301, 302, 405].includes(response.status)) {
        continue;
      }

      if (response.status >= 200 && response.status < 300) {
        continue;
      }

      const detail = await decodeResponseTextSafe(response);
      throw new Error(`WebDAV MKCOL failed (${response.status}): ${detail || 'Unknown error'}`);
    }
  }

  async upload({ storageKey, buffer, mimeType, fileName }) {
    this.validate();

    await this.ensureCollectionPath(storageKey);

    const response = await this.fetchDav('PUT', storageKey, {
      headers: {
        'Content-Type': mimeType || 'application/octet-stream',
        'Content-Length': String(buffer.byteLength),
        'X-Upload-Filename': fileName || storageKey || '',
      },
      body: buffer,
    });

    if (!response.ok && ![201, 204].includes(response.status)) {
      const detail = await decodeResponseTextSafe(response);
      throw new Error(`WebDAV upload failed (${response.status}): ${detail || 'Unknown error'}`);
    }

    return {
      storageKey,
      metadata: {
        webdavPath: [...this.buildSegments(storageKey)].join('/'),
        etag: response.headers.get('etag') || null,
      },
    };
  }

  async download({ storageKey, range }) {
    this.validate();

    const headers = {};
    if (range) headers.Range = range;

    const response = await this.fetchDav('GET', storageKey, { headers });
    if (!response.ok && response.status !== 206) {
      if (response.status === 404) return null;
      const detail = await decodeResponseTextSafe(response);
      throw new Error(`WebDAV download failed (${response.status}): ${detail || 'Unknown error'}`);
    }
    return response;
  }

  async delete({ storageKey }) {
    this.validate();

    const response = await this.fetchDav('DELETE', storageKey);
    if (response.ok || response.status === 404) return true;

    const detail = await decodeResponseTextSafe(response);
    throw new Error(`WebDAV delete failed (${response.status}): ${detail || 'Unknown error'}`);
  }
}

module.exports = {
  WebDAVStorageAdapter,
};
