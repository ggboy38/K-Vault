function normalizeToken(value) {
  if (!value) return '';
  return String(value).replace(/^Bearer\s+/i, '').trim();
}

function normalizePath(value) {
  return String(value || '')
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '')
    .replace(/\/{2,}/g, '/');
}

function encodeGraphPath(path) {
  const normalized = normalizePath(path);
  if (!normalized) return '';
  return normalized.split('/').map((segment) => encodeURIComponent(segment)).join('/');
}

async function parseGraphError(response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const json = await response.json().catch(() => ({}));
    if (json?.error?.message) return json.error.message;
    if (json?.message) return json.message;
    return JSON.stringify(json);
  }
  return response.text().catch(() => '');
}

class OneDriveStorageAdapter {
  constructor(config) {
    this.type = 'onedrive';
    this.config = {
      accessToken: normalizeToken(config.accessToken || config.token),
      tenantId: String(config.tenantId || '').trim(),
      clientId: String(config.clientId || '').trim(),
      clientSecret: String(config.clientSecret || '').trim(),
      driveId: String(config.driveId || '').trim(),
      folderPath: normalizePath(config.folderPath || config.rootPath || config.path || config.prefix),
    };

    this.cachedToken = null;
  }

  validate() {
    const hasClientCredentials = Boolean(
      this.config.tenantId && this.config.clientId && this.config.clientSecret
    );

    if (!this.config.accessToken && !hasClientCredentials) {
      throw new Error('OneDrive storage requires accessToken, or tenantId + clientId + clientSecret.');
    }

    if (!this.config.accessToken && !this.config.driveId) {
      throw new Error('OneDrive client-credentials mode requires driveId.');
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

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(this.config.tenantId)}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: 'https://graph.microsoft.com/.default',
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const json = await response.json().catch(() => ({}));
    if (!response.ok || !json.access_token) {
      throw new Error(
        json.error_description || json.error || `OneDrive token exchange failed (${response.status}).`
      );
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

  driveBasePath() {
    if (this.config.driveId) {
      return `/drives/${encodeURIComponent(this.config.driveId)}`;
    }
    return '/me/drive';
  }

  graphApi(pathname) {
    return `https://graph.microsoft.com/v1.0${pathname}`;
  }

  resolvePath(storageKey = '') {
    const keyPath = normalizePath(storageKey);
    if (!this.config.folderPath) return keyPath;
    return keyPath ? `${this.config.folderPath}/${keyPath}` : this.config.folderPath;
  }

  contentUrlByPath(path) {
    return this.graphApi(`${this.driveBasePath()}/root:/${encodeGraphPath(path)}:/content`);
  }

  itemUrlByPath(path) {
    return this.graphApi(`${this.driveBasePath()}/root:/${encodeGraphPath(path)}:`);
  }

  itemUrlById(itemId) {
    return this.graphApi(`${this.driveBasePath()}/items/${encodeURIComponent(itemId)}`);
  }

  async fetchContentUrl(url, headers = {}) {
    const response = await fetch(url, {
      headers: await this.authHeaders(headers),
      redirect: 'manual',
    });

    if (response.status === 301 || response.status === 302) {
      const location = response.headers.get('location');
      if (!location) throw new Error('OneDrive content redirect URL missing.');
      return fetch(location, {
        headers: headers.Range ? { Range: headers.Range } : {},
        redirect: 'follow',
      });
    }

    return response;
  }

  async testConnection() {
    this.validate();

    const driveResponse = await fetch(this.graphApi(`${this.driveBasePath()}?$select=id,name,driveType`), {
      headers: await this.authHeaders(),
    });

    if (!driveResponse.ok) {
      const detail = await parseGraphError(driveResponse);
      return {
        connected: false,
        status: driveResponse.status,
        detail: detail || 'Cannot access OneDrive/Graph drive endpoint.',
      };
    }

    if (this.config.folderPath) {
      const folderResponse = await fetch(
        `${this.itemUrlByPath(this.config.folderPath)}?$select=id,name,folder`,
        { headers: await this.authHeaders() }
      );

      if (!folderResponse.ok) {
        const detail = await parseGraphError(folderResponse);
        return {
          connected: false,
          status: folderResponse.status,
          detail: detail || `Cannot access folderPath "${this.config.folderPath}".`,
        };
      }
    }

    const driveJson = await driveResponse.json().catch(() => ({}));
    return {
      connected: true,
      status: driveResponse.status,
      driveId: driveJson.id || this.config.driveId || '',
      authMode: this.config.accessToken ? 'access_token' : 'client_credentials',
    };
  }

  async upload({ storageKey, buffer, mimeType }) {
    this.validate();

    const path = this.resolvePath(storageKey);
    if (!path) {
      throw new Error('OneDrive upload requires storageKey or folderPath.');
    }

    const response = await fetch(this.contentUrlByPath(path), {
      method: 'PUT',
      headers: await this.authHeaders({
        'Content-Type': mimeType || 'application/octet-stream',
      }),
      body: buffer,
    });

    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(`OneDrive upload failed (${response.status}): ${json?.error?.message || 'Unknown error'}`);
    }

    return {
      storageKey,
      metadata: {
        onedriveItemId: json.id || null,
        onedrivePath: path,
        onedriveETag: json.eTag || null,
      },
    };
  }

  async download({ storageKey, metadata = {}, range }) {
    this.validate();

    let url = null;
    if (metadata.onedriveItemId) {
      url = `${this.itemUrlById(metadata.onedriveItemId)}/content`;
    } else {
      const path = metadata.onedrivePath || this.resolvePath(storageKey);
      if (!path) return null;
      url = this.contentUrlByPath(path);
    }

    const headers = {};
    if (range) headers.Range = range;

    const response = await this.fetchContentUrl(url, headers);
    if (!response.ok && response.status !== 206) {
      if (response.status === 404) return null;
      const detail = await parseGraphError(response);
      throw new Error(`OneDrive download failed (${response.status}): ${detail}`);
    }

    return response;
  }

  async delete({ storageKey, metadata = {} }) {
    this.validate();

    let url = null;
    if (metadata.onedriveItemId) {
      url = this.itemUrlById(metadata.onedriveItemId);
    } else {
      const path = metadata.onedrivePath || this.resolvePath(storageKey);
      if (!path) return true;
      url = this.itemUrlByPath(path);
    }

    const response = await fetch(url, {
      method: 'DELETE',
      headers: await this.authHeaders(),
    });

    if (response.ok || response.status === 404 || response.status === 204) return true;
    const detail = await parseGraphError(response);
    throw new Error(`OneDrive delete failed (${response.status}): ${detail}`);
  }
}

module.exports = {
  OneDriveStorageAdapter,
};
