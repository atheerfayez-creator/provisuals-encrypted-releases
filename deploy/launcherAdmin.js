import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { createReadStream, mkdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { basename, extname, join, resolve } from 'node:path';
import { AuditAction } from '@prisma/client';
import { Router } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { AppError } from '../../utils/errors.js';
const releaseSchema = z.object({
    version: z
        .string()
        .trim()
        .regex(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/),
    releaseNotes: z.string().trim().max(4000).optional().default('')
});
const remoteReleaseSchema = releaseSchema.extend({
    downloadUrl: z.string().trim().regex(/^(?:r2:\/\/[a-z0-9][a-z0-9.-]{1,62}\/[A-Za-z0-9][A-Za-z0-9._\/-]{0,1023}|ghrel:\/\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.json)$/i, 'Use a private vault reference such as ghrel://owner/repository/v1.6.7/manifest.json.').refine((value) => !value.includes('/../') && !value.endsWith('/..'), 'Private object reference cannot contain parent paths.'),
    fileName: z.string().trim().min(1).max(180).refine((value) => extname(value).toLowerCase() === '.zip', 'File name must end in .zip.'),
    sha256: z.string().trim().regex(/^[a-fA-F0-9]{64}$/).transform((value) => value.toLowerCase()),
    sizeBytes: z.coerce.number().int().positive().max(8 * 1024 * 1024 * 1024)
});
const storageRoot = resolve(env.LAUNCHER_RELEASE_STORAGE_PATH);
const incomingRoot = join(storageRoot, '.incoming');
mkdirSync(incomingRoot, { recursive: true });
const upload = multer({
    storage: multer.diskStorage({
        destination: (_req, _file, callback) => callback(null, incomingRoot),
        filename: (_req, _file, callback) => callback(null, randomUUID())
    }),
    limits: { fileSize: env.LAUNCHER_UPLOAD_MAX_MB * 1024 * 1024, files: 1 }
});
export function createLauncherAdminRouter(deps) {
    const router = Router();
    router.get('/admin/downloads', (_req, res) => {
        res.type('html').send(DOWNLOADS_HTML);
    });
    router.get('/admin/downloads/assets/styles.css', (_req, res) => {
        res.type('css').send(DOWNLOADS_CSS);
    });
    router.get('/admin/downloads/assets/app.js', (_req, res) => {
        res.type('application/javascript').send(DOWNLOADS_JS);
    });
    router.use('/admin/api/releases', requireAdminToken);
    router.get('/admin/api/releases', asyncHandler(async (_req, res) => {
        const [products, launcherReleases] = await Promise.all([
            deps.prisma.product.findMany({
                orderBy: { name: 'asc' },
                include: { releases: { orderBy: { createdAt: 'desc' } } }
            }),
            deps.prisma.launcherRelease.findMany({ orderBy: { createdAt: 'desc' } })
        ]);
        res.json({ ok: true, products, launcherReleases });
    }));
    router.post('/admin/api/releases/products/:productId', uploadSingle, asyncHandler(async (req, res) => {
        const uploaded = requireUpload(req, '.zip');
        try {
            const productId = z.uuid().parse(req.params['productId']);
            const body = releaseSchema.parse(req.body);
            const product = await deps.prisma.product.findUnique({ where: { id: productId } });
            if (!product)
                throw new AppError('Product not found.', 'PRODUCT_NOT_FOUND', 404);
            const existing = await deps.prisma.productRelease.findUnique({
                where: { productId_version: { productId, version: body.version } }
            });
            if (existing)
                throw new AppError('That product version is already published.', 'RELEASE_EXISTS', 409);
            const releaseId = randomUUID();
            const destinationDir = join(storageRoot, 'products', productId);
            mkdirSync(destinationDir, { recursive: true });
            const destination = join(destinationDir, `${releaseId}.zip`);
            const sha256 = await hashFile(uploaded.path);
            const sizeBytes = statSync(uploaded.path).size;
            renameSync(uploaded.path, destination);
            const release = await deps.prisma.$transaction(async (tx) => {
                await tx.productRelease.updateMany({
                    where: { productId, published: true },
                    data: { published: false }
                });
                return tx.productRelease.create({
                    data: {
                        id: releaseId,
                        productId,
                        version: body.version,
                        fileName: `${safeName(product.code)}-${body.version}.zip`,
                        storagePath: destination,
                        sha256,
                        sizeBytes,
                        releaseNotes: body.releaseNotes || null,
                        published: true
                    }
                });
            });
            await deps.auditService.record({
                action: AuditAction.PRODUCT_RELEASE_PUBLISHED,
                productId,
                actorDiscordId: env.ADMIN_PANEL_ACTOR_DISCORD_ID || null,
                metadata: { version: release.version, sha256, sizeBytes }
            });
            res.status(201).json({ ok: true, release });
        }
        catch (error) {
            rmSync(uploaded.path, { force: true });
            throw error;
        }
    }));
    router.post('/admin/api/releases/products/:productId/remote', asyncHandler(async (req, res) => {
        const productId = z.uuid().parse(req.params['productId']);
        const body = remoteReleaseSchema.parse(req.body);
        const product = await deps.prisma.product.findUnique({ where: { id: productId } });
        if (!product)
            throw new AppError('Product not found.', 'PRODUCT_NOT_FOUND', 404);
        const existing = await deps.prisma.productRelease.findUnique({
            where: { productId_version: { productId, version: body.version } }
        });
        if (existing)
            throw new AppError('That product version is already published.', 'RELEASE_EXISTS', 409);
        const release = await deps.prisma.$transaction(async (tx) => {
            await tx.productRelease.updateMany({
                where: { productId, published: true },
                data: { published: false }
            });
            return tx.productRelease.create({
                data: {
                    productId,
                    version: body.version,
                    fileName: safeName(body.fileName),
                    storagePath: '',
                    downloadUrl: body.downloadUrl,
                    sha256: body.sha256,
                    sizeBytes: body.sizeBytes,
                    releaseNotes: body.releaseNotes || null,
                    published: true
                }
            });
        });
        await deps.auditService.record({
            action: AuditAction.PRODUCT_RELEASE_PUBLISHED,
            productId,
            actorDiscordId: env.ADMIN_PANEL_ACTOR_DISCORD_ID || null,
            metadata: { version: release.version, sha256: release.sha256, sizeBytes: release.sizeBytes, storage: 'remote' }
        });
        res.status(201).json({ ok: true, release });
    }));
    router.post('/admin/api/releases/launcher', uploadSingle, asyncHandler(async (req, res) => {
        const uploaded = requireUpload(req, '.exe');
        try {
            const body = releaseSchema.pick({ version: true }).parse(req.body);
            const existing = await deps.prisma.launcherRelease.findUnique({
                where: { version: body.version }
            });
            if (existing)
                throw new AppError('That launcher version is already published.', 'RELEASE_EXISTS', 409);
            const releaseId = randomUUID();
            const destinationDir = join(storageRoot, 'launcher');
            mkdirSync(destinationDir, { recursive: true });
            const destination = join(destinationDir, `${releaseId}.exe`);
            const sha256 = await hashFile(uploaded.path);
            const sizeBytes = statSync(uploaded.path).size;
            renameSync(uploaded.path, destination);
            const release = await deps.prisma.$transaction(async (tx) => {
                await tx.launcherRelease.updateMany({
                    where: { published: true },
                    data: { published: false }
                });
                return tx.launcherRelease.create({
                    data: {
                        id: releaseId,
                        version: body.version,
                        fileName: `ProVisuals-Launcher-Setup-${body.version}-x64.exe`,
                        storagePath: destination,
                        sha256,
                        sizeBytes,
                        published: true
                    }
                });
            });
            await deps.auditService.record({
                action: AuditAction.LAUNCHER_RELEASE_PUBLISHED,
                actorDiscordId: env.ADMIN_PANEL_ACTOR_DISCORD_ID || null,
                metadata: { version: release.version, sha256, sizeBytes }
            });
            res.status(201).json({ ok: true, release });
        }
        catch (error) {
            rmSync(uploaded.path, { force: true });
            throw error;
        }
    }));
    return router;
}
function uploadSingle(req, res, next) {
    upload.single('file')(req, res, (error) => {
        if (!error)
            return next();
        if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
            next(new AppError(`Upload exceeds ${env.LAUNCHER_UPLOAD_MAX_MB} MB.`, 'UPLOAD_TOO_LARGE', 413));
            return;
        }
        next(new AppError('The release upload could not be processed.', 'UPLOAD_FAILED', 400));
    });
}
function requireUpload(req, requiredExtension) {
    if (!req.file)
        throw new AppError('Choose a release file to upload.', 'FILE_REQUIRED', 400);
    if (extname(req.file.originalname).toLowerCase() !== requiredExtension) {
        rmSync(req.file.path, { force: true });
        throw new AppError(`The uploaded file must be ${requiredExtension}.`, 'INVALID_FILE_TYPE', 400);
    }
    return req.file;
}
function requireAdminToken(req, res, next) {
    const expected = env.ADMIN_PANEL_TOKEN;
    const provided = req.header('x-admin-token')?.trim();
    if (!expected || !provided || !safeEqual(provided, expected)) {
        res
            .status(provided ? 403 : 401)
            .json({ ok: false, message: 'A valid admin token is required.' });
        return;
    }
    next();
}
function safeEqual(left, right) {
    const a = Buffer.from(left, 'utf8');
    const b = Buffer.from(right, 'utf8');
    if (a.length !== b.length) {
        const padding = Buffer.alloc(Math.max(a.length, b.length, 32));
        timingSafeEqual(padding, padding);
        return false;
    }
    return timingSafeEqual(a, b);
}
function hashFile(path) {
    return new Promise((resolveHash, reject) => {
        const hash = createHash('sha256');
        const stream = createReadStream(path);
        stream.on('error', reject);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolveHash(hash.digest('hex')));
    });
}
function safeName(value) {
    return basename(value).replace(/[^A-Za-z0-9._-]+/g, '-');
}
function asyncHandler(handler) {
    return (req, res, next) => {
        void handler(req, res).catch(next);
    };
}
const DOWNLOADS_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ProVisuals Downloads</title><link rel="stylesheet" href="/admin/downloads/assets/styles.css"><script type="module" src="/admin/downloads/assets/app.js"></script></head><body><main><nav><a href="/admin">Licenses</a><span>·</span><a href="/admin/downloads">Downloads</a></nav><header><p>PRIVATE ADMIN PANEL</p><h1>Release downloads</h1><p>Publish launcher builds and Assetto Corsa product ZIPs. Customers only receive products connected to their account license.</p></header><section id="login"><label>Admin token<input id="token" type="password" autocomplete="current-password"></label><button id="unlock">Unlock</button></section><section id="panel" hidden><div class="grid"><form id="launcher-form"><h2>Launcher installer</h2><label>Version<input name="version" placeholder="1.0.1" required></label><label>Windows installer<input name="file" type="file" accept=".exe" required></label><button>Publish launcher</button></form><form id="product-form"><h2>Small product upload</h2><label>Product<select name="productId" id="products" required></select></label><label>Version<input name="version" placeholder="1.0.0" required></label><label>Release notes<textarea name="releaseNotes"></textarea></label><label>Assetto Corsa ZIP<input name="file" type="file" accept=".zip" required></label><button>Publish product</button></form><form id="remote-product-form"><h2>Large licensed product</h2><p>Use the encrypted release vault. A leaked asset link contains only AES-256-GCM ciphertext and cannot install without launcher authorization.</p><label>Product<select name="productId" id="remote-products" required></select></label><label>Version<input name="version" placeholder="1.6.7" required></label><label>Release notes<textarea name="releaseNotes"></textarea></label><label>ZIP file name<input name="fileName" placeholder="ProSeasons-1.6.7.zip" required></label><label>Encrypted vault reference<input name="downloadUrl" type="text" placeholder="ghrel://owner/repository/v1.6.7/manifest.json" required></label><label>SHA-256<input name="sha256" minlength="64" maxlength="64" required></label><label>Size in bytes<input name="sizeBytes" type="number" min="1" required></label><button>Publish encrypted product</button></form></div><div id="status" role="status"></div><section><h2>Published releases</h2><div id="releases"></div></section><button id="lock" class="quiet">Lock panel</button></section></main></body></html>`;
const DOWNLOADS_CSS = `:root{color-scheme:dark;font-family:Inter,Segoe UI,sans-serif;background:#0b0d0f;color:#eef0f2}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#31130f 0,transparent 36%),#0b0d0f}main{max-width:1080px;margin:auto;padding:40px 24px}nav{display:flex;gap:10px;color:#8f979f}a{color:#ef6a4c}header{margin:44px 0 28px}header>p:first-child{color:#ef6a4c;font-size:12px;letter-spacing:.16em}h1{font-size:42px;margin:8px 0}header p{color:#9ca3aa;max-width:720px}section,form{background:#121519;border:1px solid #292e34;border-radius:14px;padding:22px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.grid form{background:#0f1215}label{display:grid;gap:7px;margin:14px 0;color:#aeb4ba}input,select,textarea{width:100%;border:1px solid #343a41;border-radius:8px;background:#090b0d;color:#fff;padding:11px}textarea{min-height:88px}button{border:0;border-radius:8px;background:#e84a2a;color:#fff;padding:11px 16px;font-weight:700;cursor:pointer}.quiet{margin-top:18px;background:#272c31}#status{min-height:26px;margin:18px 0;color:#74d99f}.error{color:#ff8170!important}.release{display:grid;grid-template-columns:1fr auto;gap:10px;padding:12px 0;border-bottom:1px solid #292e34}.release span{color:#969da4}@media(max-width:760px){.grid{grid-template-columns:1fr}h1{font-size:34px}}`;
const DOWNLOADS_JS = `const key='provisuals_admin_token';const token=document.querySelector('#token');const login=document.querySelector('#login');const panel=document.querySelector('#panel');const status=document.querySelector('#status');const products=document.querySelector('#products');const remoteProducts=document.querySelector('#remote-products');token.value=localStorage.getItem(key)||'';document.querySelector('#unlock').onclick=()=>load();document.querySelector('#lock').onclick=()=>{localStorage.removeItem(key);location.reload()};document.querySelector('#launcher-form').onsubmit=e=>upload(e,'/launcher');document.querySelector('#product-form').onsubmit=e=>upload(e,'/products/'+encodeURIComponent(new FormData(e.currentTarget).get('productId')));document.querySelector('#remote-product-form').onsubmit=publishRemote;async function api(path,options={}){const headers=new Headers(options.headers||{});headers.set('X-Admin-Token',token.value);const response=await fetch('/admin/api/releases'+path,{...options,headers});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.message||'Request failed');return data}function productOptions(data){return data.products.map(p=>{const o=document.createElement('option');o.value=p.id;o.textContent=p.name+' ('+p.code+')';return o})}async function load(){try{localStorage.setItem(key,token.value);const data=await api('');login.hidden=true;panel.hidden=false;products.replaceChildren(...productOptions(data));remoteProducts.replaceChildren(...productOptions(data));const rows=[];for(const item of data.launcherReleases)rows.push(['Launcher',item.version,item.sizeBytes,item.published,'server']);for(const p of data.products)for(const item of p.releases)rows.push([p.name,item.version,item.sizeBytes,item.published,item.downloadUrl?'remote':'server']);document.querySelector('#releases').replaceChildren(...rows.map(row=>{const d=document.createElement('div');d.className='release';const strong=document.createElement('strong');strong.textContent=row[0]+' '+row[1]+(row[3]?' · LIVE':'');const span=document.createElement('span');span.textContent=(row[2]/1048576).toFixed(1)+' MB · '+row[4];d.append(strong,span);return d}));setStatus('Release data loaded.')}catch(e){setStatus(e.message,true)}}async function upload(event,path){event.preventDefault();const form=event.currentTarget;const button=form.querySelector('button');button.disabled=true;try{setStatus('Uploading and verifying…');await api(path,{method:'POST',body:new FormData(form)});form.reset();await load();setStatus('Release published successfully.')}catch(e){setStatus(e.message,true)}finally{button.disabled=false}}async function publishRemote(event){event.preventDefault();const form=event.currentTarget;const button=form.querySelector('button');const values=Object.fromEntries(new FormData(form));const productId=values.productId;delete values.productId;values.sizeBytes=Number(values.sizeBytes);button.disabled=true;try{setStatus('Publishing private-storage release…');await api('/products/'+encodeURIComponent(productId)+'/remote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(values)});form.reset();await load();setStatus('Remote release published successfully.')}catch(e){setStatus(e.message,true)}finally{button.disabled=false}}function setStatus(message,error=false){status.textContent=message;status.className=error?'error':''}if(token.value)load();`;
