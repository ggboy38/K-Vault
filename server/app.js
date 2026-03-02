const { Hono } = require('hono');
const { cors } = require('hono/cors');
const { createContainer } = require('./lib/container');

function createApp() {
  const app = new Hono();
  const container = createContainer(process.env);

  app.use('*', cors({
    origin: (origin) => origin || '*',
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Range'],
    exposeHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges', 'Content-Disposition'],
    credentials: true,
  }));

  app.use('*', async (c, next) => {
    c.set('container', container);
    try {
      await next();
    } catch (error) {
      console.error(error);
      return c.json({ error: error.message || 'Internal Server Error' }, 500);
    }
  });

  function getServices(c) {
    return c.get('container');
  }

  function asString(value, fallback = '') {
    if (value == null) return fallback;
    if (Array.isArray(value)) return asString(value[0], fallback);
    if (value instanceof File) return fallback;
    return String(value);
  }

  function firstNonEmpty(...values) {
    for (const value of values) {
      if (value == null) continue;
      if (Array.isArray(value)) {
        const nested = firstNonEmpty(...value);
        if (nested != null) return nested;
        continue;
      }
      if (value instanceof File) continue;
      const normalized = String(value).trim();
      if (normalized) return normalized;
    }
    return '';
  }

  function parseBoundedInt(value, fallback, min = 1, max = 1000) {
    const parsed = Number.parseInt(String(value || ''), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
  }

  function authResult(c) {
    const { authService } = getServices(c);
    return authService.checkAuthentication(c.req.raw);
  }

  function isTruthy(value) {
    if (value == null) return false;
    const normalized = String(value).trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
  }

  function requireAuth(c) {
    const result = authResult(c);
    if (!result.authenticated) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    c.set('auth', result);
    return null;
  }

  function sanitizeSettingEntries(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return {};
    }

    const output = {};
    for (const [rawKey, value] of Object.entries(input)) {
      const key = String(rawKey || '').trim();
      if (!key) continue;
      output[key] = value;
    }
    return output;
  }

  function getSettingsKeyList(c) {
    const list = [];
    const rawSingle = c.req.query('key');
    const rawList = c.req.query('keys');

    if (rawSingle) {
      list.push(String(rawSingle));
    }
    if (rawList) {
      for (const key of String(rawList).split(',')) {
        list.push(key);
      }
    }

    return list
      .map((key) => String(key || '').trim())
      .filter(Boolean);
  }

  // --- Auth ---
  app.get('/api/auth/check', (c) => {
    const { authService, guestService } = getServices(c);
    const auth = authService.checkAuthentication(c.req.raw);

    return c.json({
      authenticated: auth.authenticated,
      authRequired: authService.isAuthRequired(),
      reason: auth.reason,
      guestUpload: guestService.getConfig(),
    });
  });

  app.post('/api/auth/login', async (c) => {
    const { authService } = getServices(c);

    if (!authService.isAuthRequired()) {
      return c.json({ success: true, authRequired: false, message: 'No login required.' });
    }

    const body = await c.req.json().catch(() => ({}));
    const username = firstNonEmpty(body.username, body.user);
    const password = String(body.password ?? body.pass ?? '');

    if (!username || password === '') {
      return c.json({ success: false, message: 'Missing username or password.' }, 400);
    }

    if (username !== container.config.basicUser || password !== container.config.basicPass) {
      return c.json({ success: false, message: 'Invalid username or password.' }, 401);
    }

    const session = authService.createSession(username);
    c.header('Set-Cookie', authService.createSessionCookie(session.token));

    return c.json({ success: true, message: 'Login successful.' });
  });

  app.post('/api/auth/logout', (c) => {
    const { authService } = getServices(c);
    const token = authService.getSessionTokenFromRequest(c.req.raw);
    authService.deleteSession(token);

    const clearCookies = authService.createClearSessionCookies();
    const response = c.json({ success: true, message: 'Logged out.' });
    response.headers.append('Set-Cookie', clearCookies[0]);
    response.headers.append('Set-Cookie', clearCookies[1]);
    return response;
  });

  app.get('/api/auth/login', (c) => {
    const { authService } = getServices(c);
    return c.json({
      authRequired: authService.isAuthRequired(),
    });
  });

  // Compatibility aliases
  app.get('/api/manage/check', (c) => {
    const { authService } = getServices(c);
    return c.text(authService.isAuthRequired() ? 'true' : 'Not using basic auth.');
  });

  app.get('/api/manage/login', (c) => {
    const auth = authResult(c);
    if (auth.authenticated) {
      return c.redirect('/admin.html', 302);
    }
    return c.redirect('/login.html?redirect=%2Fadmin.html', 302);
  });

  const handleManageLogout = (c) => {
    const { authService } = getServices(c);
    const token = authService.getSessionTokenFromRequest(c.req.raw);
    authService.deleteSession(token);
    const clearCookies = authService.createClearSessionCookies();
    const response = c.redirect('/login.html', 302);
    response.headers.append('Set-Cookie', clearCookies[0]);
    response.headers.append('Set-Cookie', clearCookies[1]);
    return response;
  };
  app.get('/api/manage/logout', handleManageLogout);
  app.post('/api/manage/logout', handleManageLogout);

  const getSettingsHandler = async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { settingsStore } = getServices(c);
    const keys = getSettingsKeyList(c);
    const settings = keys.length > 0
      ? await settingsStore.getMany(keys)
      : await settingsStore.getAll();

    return c.json({ success: true, settings });
  };

  const setSettingsHandler = async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { settingsStore } = getServices(c);
    const body = await c.req.json().catch(() => ({}));
    const source = body.settings != null ? body.settings : body;
    const settings = sanitizeSettingEntries(source);
    const removeKeys = Array.isArray(body.removeKeys)
      ? body.removeKeys.map((key) => String(key || '').trim()).filter(Boolean)
      : [];

    if (Object.keys(settings).length > 0) {
      await settingsStore.setMany(settings);
    }
    if (removeKeys.length > 0) {
      await settingsStore.deleteMany(removeKeys);
    }

    return c.json({
      success: true,
      settings: await settingsStore.getAll(),
    });
  };

  const deleteSettingsHandler = async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { settingsStore } = getServices(c);
    const queryKeys = getSettingsKeyList(c);
    let payloadKeys = [];

    if (queryKeys.length === 0) {
      const body = await c.req.json().catch(() => ({}));
      if (Array.isArray(body.keys)) {
        payloadKeys = body.keys.map((key) => String(key || '').trim()).filter(Boolean);
      }
    }

    const keys = queryKeys.length > 0 ? queryKeys : payloadKeys;
    if (keys.length === 0) {
      return c.json({ error: 'No setting keys provided.' }, 400);
    }

    await settingsStore.deleteMany(keys);

    return c.json({
      success: true,
      settings: await settingsStore.getAll(),
    });
  };

  app.get('/api/settings', getSettingsHandler);
  app.put('/api/settings', setSettingsHandler);
  app.patch('/api/settings', setSettingsHandler);
  app.delete('/api/settings', deleteSettingsHandler);

  // Compatibility aliases
  app.get('/api/manage/settings', getSettingsHandler);
  app.post('/api/manage/settings', setSettingsHandler);

  // --- Storage configs ---
  app.get('/api/storage/list', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo } = getServices(c);
    return c.json({ success: true, items: storageRepo.list(false) });
  });

  app.post('/api/storage', async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo } = getServices(c);
    const body = await c.req.json();

    const created = storageRepo.create({
      name: body.name,
      type: body.type,
      config: body.config || {},
      enabled: body.enabled !== false,
      isDefault: Boolean(body.isDefault),
      metadata: body.metadata || {},
    });

    return c.json({ success: true, item: storageRepo.getById(created.id, false) });
  });

  app.put('/api/storage/:id', async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo } = getServices(c);
    const id = c.req.param('id');
    const body = await c.req.json();

    const updated = storageRepo.update(id, {
      name: body.name,
      type: body.type,
      config: body.config,
      enabled: body.enabled,
      isDefault: body.isDefault,
      metadata: body.metadata,
    });

    if (!updated) return c.json({ error: 'Storage config not found.' }, 404);

    return c.json({ success: true, item: storageRepo.getById(id, false) });
  });

  app.delete('/api/storage/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo } = getServices(c);
    const id = c.req.param('id');
    let deleted = false;
    try {
      deleted = storageRepo.delete(id);
    } catch (error) {
      return c.json({ error: error.message }, 409);
    }

    if (!deleted) return c.json({ error: 'Storage config not found.' }, 404);
    return c.json({ success: true });
  });

  app.post('/api/storage/:id/test', async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo, storageFactory } = getServices(c);
    const id = c.req.param('id');
    const item = storageRepo.getById(id, true);
    if (!item) return c.json({ error: 'Storage config not found.' }, 404);

    const adapter = storageFactory.createAdapter(item);
    const result = await adapter.testConnection();

    return c.json({ success: true, result });
  });

  app.post('/api/storage/default/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageRepo } = getServices(c);
    const id = c.req.param('id');
    const item = storageRepo.setDefault(id);
    if (!item) return c.json({ error: 'Storage config not found.' }, 404);

    return c.json({ success: true, item: storageRepo.getById(id, false) });
  });

  app.post('/api/storage/test', async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { storageFactory } = getServices(c);
    const body = await c.req.json();
    const adapter = storageFactory.createTemporaryAdapter(body.type, body.config || {});
    const result = await adapter.testConnection();

    return c.json({ success: true, result });
  });

  // --- Status ---
  app.get('/api/status', async (c) => {
    const { storageRepo, storageFactory, authService, guestService, settingsStore } = getServices(c);

    const status = {
      telegram: { connected: false, message: 'Not configured' },
      kv: { connected: true, message: 'SQLite metadata storage enabled' },
      r2: { connected: false, enabled: false, message: 'Not configured' },
      s3: { connected: false, enabled: false, message: 'Not configured' },
      discord: { connected: false, enabled: false, message: 'Not configured' },
      huggingface: { connected: false, enabled: false, message: 'Not configured' },
      webdav: { connected: false, enabled: false, message: 'Not configured' },
      github: { connected: false, enabled: false, message: 'Not configured' },
      gdrive: { connected: false, enabled: false, message: 'Not configured' },
      onedrive: { connected: false, enabled: false, message: 'Not configured' },
      auth: {
        enabled: authService.isAuthRequired(),
        message: authService.isAuthRequired() ? 'Password auth enabled' : 'No auth required',
      },
      guestUpload: guestService.getConfig(),
      settings: { connected: false, message: 'Unknown' },
    };

    status.settings = await settingsStore.healthCheck();

    const byType = {
      telegram: storageRepo.findEnabledByType('telegram')[0],
      r2: storageRepo.findEnabledByType('r2')[0],
      s3: storageRepo.findEnabledByType('s3')[0],
      discord: storageRepo.findEnabledByType('discord')[0],
      huggingface: storageRepo.findEnabledByType('huggingface')[0],
      webdav: storageRepo.findEnabledByType('webdav')[0],
      github: storageRepo.findEnabledByType('github')[0],
      gdrive: storageRepo.findEnabledByType('gdrive')[0],
      onedrive: storageRepo.findEnabledByType('onedrive')[0],
    };

    for (const [type, storageConfig] of Object.entries(byType)) {
      if (!storageConfig) continue;
      try {
        const adapter = storageFactory.createAdapter(storageConfig);
        const result = await adapter.testConnection();
        status[type] = {
          connected: Boolean(result.connected),
          enabled: Boolean(result.connected),
          message: result.connected
            ? `Connected (${storageConfig.name})`
            : (result.detail ? `Connection failed: ${result.detail}` : 'Connection failed'),
        };
      } catch (error) {
        status[type] = {
          connected: false,
          enabled: false,
          message: `Connection error: ${error.message}`,
        };
      }
    }

    return c.json(status);
  });

  // --- Upload ---
  app.post('/upload', async (c) => {
    const { authService, guestService, uploadService } = getServices(c);
    const auth = authService.checkAuthentication(c.req.raw);

    const body = await c.req.parseBody();
    const file = body.file;
    if (!(file instanceof File)) {
      return c.json({ error: 'No file uploaded.' }, 400);
    }

    const fileBuffer = await file.arrayBuffer();
    const fileSize = fileBuffer.byteLength;

    if (fileSize > container.config.uploadMaxSize) {
      return c.json({ error: `File exceeds upload limit (${Math.floor(container.config.uploadMaxSize / 1024 / 1024)}MB).` }, 413);
    }

    if (!auth.authenticated) {
      const guestCheck = guestService.checkUploadAllowed(c.req.raw, fileSize);
      if (!guestCheck.allowed) {
        return c.json({ error: guestCheck.reason }, guestCheck.status || 403);
      }
    }

    const result = await uploadService.uploadFile({
      fileName: file.name,
      mimeType: file.type,
      fileSize,
      buffer: fileBuffer,
      storageMode: asString(body.storageMode || body.storage),
      storageId: asString(body.storageId || body.storage_config_id),
    });

    if (!auth.authenticated) {
      guestService.incrementUsage(c.req.raw);
    }

    return c.json([{ src: result.src, storageType: result.storage.type, storageId: result.storage.id }]);
  });

  app.post('/api/upload-from-url', async (c) => {
    const { authService, guestService, uploadService } = getServices(c);
    const auth = authService.checkAuthentication(c.req.raw);
    const payload = await c.req.json().catch(() => ({}));

    if (!payload.url) {
      return c.json({ error: 'url is required.' }, 400);
    }

    if (!auth.authenticated) {
      const guestCheck = guestService.checkUploadAllowed(c.req.raw, 0);
      if (!guestCheck.allowed) {
        return c.json({ error: guestCheck.reason }, guestCheck.status || 403);
      }
    }

    const result = await uploadService.uploadFromUrl({
      url: payload.url,
      storageMode: asString(payload.storageMode || payload.storage),
      storageId: asString(payload.storageId || payload.storage_config_id),
      maxBytes: Math.min(container.config.uploadSmallFileThreshold, container.config.uploadMaxSize),
    });

    if (!auth.authenticated) {
      guestService.incrementUsage(c.req.raw);
    }

    return c.json([{ src: result.src, storageType: result.storage.type, storageId: result.storage.id }]);
  });

  // --- Chunk upload ---
  app.post('/api/chunked-upload/init', async (c) => {
    const { authService, chunkService } = getServices(c);
    const auth = authService.checkAuthentication(c.req.raw);
    if (!auth.authenticated && authService.isAuthRequired()) {
      return c.json({ error: 'Guest users cannot use chunk upload.' }, 403);
    }

    const body = await c.req.json().catch(() => ({}));
    const fileSize = Number(body.fileSize || 0);
    const totalChunks = Number(body.totalChunks || 0);

    if (!body.fileName || !fileSize || !totalChunks) {
      return c.json({ error: 'Missing required parameters.' }, 400);
    }

    if (fileSize > container.config.uploadMaxSize) {
      return c.json({ error: `File exceeds upload limit (${Math.floor(container.config.uploadMaxSize / 1024 / 1024)}MB).` }, 400);
    }

    const init = chunkService.initTask({
      fileName: body.fileName,
      fileSize,
      fileType: body.fileType,
      totalChunks,
      storageMode: asString(body.storageMode),
      storageId: asString(body.storageId),
    });

    return c.json({ success: true, ...init });
  });

  app.get('/api/chunked-upload/init', (c) => {
    const { chunkService } = getServices(c);
    const uploadId = c.req.query('uploadId');
    if (!uploadId) return c.json({ error: 'uploadId is required.' }, 400);

    const task = chunkService.getTask(uploadId);
    if (!task) return c.json({ error: 'Upload task not found.' }, 404);

    return c.json({ success: true, task });
  });

  app.post('/api/chunked-upload/chunk', async (c) => {
    const { authService, chunkService } = getServices(c);
    const unauthorized = authService.isAuthRequired() ? requireAuth(c) : null;
    if (unauthorized) return unauthorized;

    const body = await c.req.parseBody();
    const uploadId = asString(body.uploadId);
    const chunkIndex = Number(body.chunkIndex);
    const chunk = body.chunk;

    if (!uploadId || Number.isNaN(chunkIndex) || !(chunk instanceof File)) {
      return c.json({ error: 'Missing required parameters.' }, 400);
    }

    const buffer = await chunk.arrayBuffer();
    chunkService.saveChunk({ uploadId, chunkIndex, buffer });

    return c.json({ success: true, chunkIndex });
  });

  app.post('/api/chunked-upload/complete', async (c) => {
    const { authService, chunkService } = getServices(c);
    const unauthorized = authService.isAuthRequired() ? requireAuth(c) : null;
    if (unauthorized) return unauthorized;

    const body = await c.req.json().catch(() => ({}));
    if (!body.uploadId) return c.json({ error: 'uploadId is required.' }, 400);

    const result = await chunkService.complete(body.uploadId);

    return c.json({
      success: true,
      src: result.src,
      fileName: result.file.file_name,
      fileSize: result.file.file_size,
    });
  });

  // --- File retrieval ---
  app.get('/api/file-info/:id', (c) => {
    const { fileRepo } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const file = fileRepo.getById(id);

    if (!file) {
      return c.json({ error: 'File not found.', fileId: id }, 404);
    }

    return c.json({
      success: true,
      fileId: file.id,
      key: file.id,
      fileName: file.file_name,
      originalName: file.file_name,
      fileSize: file.file_size,
      uploadTime: file.created_at,
      storageType: file.storage_type,
      listType: file.list_type,
      label: file.label,
      liked: Boolean(file.liked),
    });
  });

  app.get('/file/:id', async (c) => {
    const { uploadService } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const range = c.req.header('range');

    const result = await uploadService.getFileResponse(id, range);
    if (!result) {
      return c.text('File not found', 404);
    }

    const upstream = result.response;
    const headers = new Headers(upstream.headers);

    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Range, Content-Type, Accept, Origin');
    headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition');
    headers.set('Cache-Control', 'no-store, max-age=0');

    if (!headers.get('content-type') && result.file.mime_type) {
      headers.set('Content-Type', result.file.mime_type);
    }

    if (!headers.get('content-disposition')) {
      const safeName = encodeURIComponent(result.file.file_name || result.file.id);
      headers.set('Content-Disposition', `inline; filename="${safeName}"; filename*=UTF-8''${safeName}`);
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  });

  app.options('/file/:id', (c) => c.body(null, 204));
  app.on('HEAD', '/file/:id', async (c) => {
    const { uploadService } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const range = c.req.header('range');

    const result = await uploadService.getFileResponse(id, range);
    if (!result) {
      return c.body(null, 404);
    }

    const upstream = result.response;
    const headers = new Headers(upstream.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Range, Content-Type, Accept, Origin');
    headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition');
    headers.set('Cache-Control', 'no-store, max-age=0');

    return new Response(null, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  });

  // --- Manage API ---
  app.get('/api/manage/list', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { fileRepo } = getServices(c);
    const limit = parseBoundedInt(
      firstNonEmpty(c.req.query('limit'), c.req.query('pageSize'), c.req.query('size')),
      100,
      1,
      1000
    );

    let cursor = firstNonEmpty(c.req.query('cursor'), c.req.query('offset'));
    if (!cursor) {
      const current = parseBoundedInt(
        firstNonEmpty(c.req.query('page'), c.req.query('current')),
        1,
        1,
        Number.MAX_SAFE_INTEGER
      );
      cursor = current > 1 ? String((current - 1) * limit) : null;
    }

    const storage = c.req.query('storage') || 'all';
    const search = c.req.query('search') || '';
    const listType = c.req.query('listType') || c.req.query('list_type') || 'all';

    const includeStatsRaw = String(c.req.query('includeStats') || c.req.query('stats') || '').toLowerCase();
    const includeStats = ['1', 'true', 'yes'].includes(includeStatsRaw);

    const payload = fileRepo.list({
      limit,
      cursor,
      includeStats,
      filters: {
        storageType: storage,
        search,
        listType,
      },
    });

    return c.json(payload);
  });

  app.get('/api/manage/toggleLike/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { fileRepo } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const file = fileRepo.getById(id);
    if (!file) return c.json({ success: false, error: 'File not found.' }, 404);

    const updated = fileRepo.updateMetadata(id, { liked: !Boolean(file.liked) });
    return c.json({ success: true, liked: Boolean(updated.liked) });
  });

  app.get('/api/manage/editName/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { fileRepo } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const newName = String(c.req.query('newName') || '').trim();

    if (!newName) return c.json({ success: false, error: 'newName is required.' }, 400);
    const updated = fileRepo.updateMetadata(id, { fileName: newName });
    if (!updated) return c.json({ success: false, error: 'File not found.' }, 404);

    return c.json({ success: true, fileName: updated.file_name, key: updated.id });
  });

  app.get('/api/manage/block/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { fileRepo } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const action = c.req.query('action');
    const nextListType = isTruthy(action) ? 'Block' : 'White';
    const updated = fileRepo.updateMetadata(id, { listType: nextListType });
    if (!updated) return c.json({ success: false, error: 'File not found.' }, 404);

    return c.json({ success: true, listType: nextListType, key: updated.id });
  });

  app.get('/api/manage/white/:id', (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { fileRepo } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const action = c.req.query('action');
    const nextListType = isTruthy(action) ? 'White' : 'None';
    const updated = fileRepo.updateMetadata(id, { listType: nextListType });
    if (!updated) return c.json({ success: false, error: 'File not found.' }, 404);

    return c.json({ success: true, listType: nextListType, key: updated.id });
  });

  app.get('/api/manage/delete/:id', async (c) => {
    const unauthorized = requireAuth(c);
    if (unauthorized) return unauthorized;

    const { uploadService } = getServices(c);
    const id = decodeURIComponent(c.req.param('id'));
    const result = await uploadService.deleteFile(id);

    if (!result.deleted) {
      return c.json({ success: false, error: 'File not found.' }, 404);
    }

    return c.json({ success: true, message: 'File deleted.', fileId: id });
  });

  // --- Misc ---
  app.get('/api/bing/wallpaper', async (c) => {
    const response = await fetch('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5');
    if (!response.ok) {
      return c.json({ status: false, message: 'Failed to fetch Bing wallpapers.' }, 502);
    }
    const json = await response.json();
    return c.json({ status: true, message: 'ok', data: json.images || [] });
  });
  app.get('/api/bing/wallpaper/', async (c) => {
    const response = await fetch('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5');
    if (!response.ok) {
      return c.json({ status: false, message: 'Failed to fetch Bing wallpapers.' }, 502);
    }
    const json = await response.json();
    return c.json({ status: true, message: 'ok', data: json.images || [] });
  });

  app.post('/api/telegram/webhook', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return c.json({ success: true, received: Boolean(body) });
  });

  app.get('/api/health', (c) => {
    return c.json({ ok: true, mode: 'docker-node', timestamp: Date.now() });
  });

  return app;
}

module.exports = {
  createApp,
};
