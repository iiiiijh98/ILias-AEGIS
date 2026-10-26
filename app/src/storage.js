'use strict';
// 사진 저장소: 로컬 디스크(data/photos) 또는 Vercel Blob(private). 사진은 로그인한 앱 경로로만 제공합니다.
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const { AppError } = require('./util');
function sniff(buf) {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'image/webp';
  if (buf.length > 12 && buf.slice(4, 8).toString() === 'ftyp' && /heic|heix|mif1|heim|heis/.test(buf.slice(8, 12).toString())) return 'image/heic';
  return null;
}
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/heic': 'heic' };
function createStorage(cfg) {
  const useBlob = !!cfg.blobToken;
  return {
    kind: useBlob ? 'vercel-blob(private)' : 'local-disk',
    async save(buf) {
      const mime = sniff(buf); if (!mime) throw new AppError('사진 파일(JPEG/PNG/WEBP/HEIC)만 올릴 수 있습니다.');
      const d = new Date(); const key = `photos/${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${crypto.randomUUID()}.${EXT[mime]}`;
      const sha = crypto.createHash('sha256').update(buf).digest('hex');
      if (useBlob) {
        const { put } = require('@vercel/blob');
        const r = await put(key, buf, { access: 'private', contentType: mime, addRandomSuffix: false, token: cfg.blobToken });
        return { storage_key: r.pathname, mime, size: buf.length, sha256: sha };
      }
      const file = path.join(cfg.photoDir, key.replace(/^photos\//, ''));
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, buf, { flag: 'wx' });
      return { storage_key: key, mime, size: buf.length, sha256: sha };
    },
    async read(key) {
      if (useBlob) {
        const { get } = require('@vercel/blob');
        const r = await get(key, { access: 'private', token: cfg.blobToken });
        if (!r || r.statusCode !== 200) return null;
        return Buffer.from(await new Response(r.stream).arrayBuffer());
      }
      const file = path.resolve(cfg.photoDir, key.replace(/^photos\//, ''));
      if (!file.startsWith(path.resolve(cfg.photoDir) + path.sep)) return null;
      return fs.existsSync(file) ? fs.readFileSync(file) : null;
    },
  };
}
module.exports = { createStorage, sniff };
