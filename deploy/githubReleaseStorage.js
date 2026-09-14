import { createDecipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { env } from '../config/env.js';
import { AppError } from '../utils/errors.js';

const API_ORIGIN = 'https://api.github.com';
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_PARTS = 64;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export async function githubReleaseStream(reference, expectedRelease) {
    const target = parseReference(reference);
    requireConfiguration(target);
    const release = await githubJson(`/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repository)}/releases/tags/${encodeURIComponent(target.tag)}`);
    const manifestAsset = findAsset(release, target.manifestName);
    const manifestResponse = await githubAssetResponse(target, manifestAsset);
    const manifest = parseManifest(await readSmallText(manifestResponse, MAX_MANIFEST_BYTES));
    validateManifest(manifest, expectedRelease);
    const assetMap = new Map((release.assets ?? []).map((asset) => [asset.name, asset]));
    const orderedAssets = manifest.parts.map((part) => {
        const asset = assetMap.get(part.name);
        if (!asset || !Number.isSafeInteger(asset.id)) {
            throw storageError(`Private release part ${part.name} is missing.`);
        }
        if (Number(asset.size) !== part.sizeBytes) {
            throw storageError(`Private release part ${part.name} has an unexpected size.`);
        }
        return { ...part, asset };
    });
    return Readable.from(streamParts(target, orderedAssets, manifest));
}

function parseReference(reference) {
    let parsed;
    try {
        parsed = new URL(reference);
    }
    catch {
        throw storageError('The private GitHub release reference is invalid.');
    }
    if (parsed.protocol !== 'ghrel:' || parsed.username || parsed.password || parsed.port || parsed.search || parsed.hash) {
        throw storageError('The private GitHub release reference is invalid.');
    }
    const segments = parsed.pathname.split('/').filter(Boolean).map((segment) => decodeURIComponent(segment));
    if (segments.length !== 3) {
        throw storageError('The private GitHub release reference must include repository, tag, and manifest.');
    }
    const [repository, tag, manifestName] = segments;
    const safeName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
    if (!safeName.test(parsed.hostname) || !safeName.test(repository) || !safeName.test(tag) || !safeName.test(manifestName) || !manifestName.endsWith('.json')) {
        throw storageError('The private GitHub release reference contains an invalid name.');
    }
    return { owner: parsed.hostname, repository, tag, manifestName };
}

function requireConfiguration(target) {
    if (!env.GITHUB_RELEASES_REPOSITORY) {
        throw new AppError('Private release storage is not configured.', 'PRIVATE_STORAGE_UNAVAILABLE', 503);
    }
    const actual = `${target.owner}/${target.repository}`.toLowerCase();
    if (actual !== env.GITHUB_RELEASES_REPOSITORY.toLowerCase()) {
        throw storageError('The private release repository is not allowed.');
    }
}

async function githubJson(path) {
    let response;
    try {
        response = await fetch(`${API_ORIGIN}${path}`, {
            headers: githubHeaders('application/vnd.github+json'),
            redirect: 'error'
        });
    }
    catch {
        throw unavailableError();
    }
    if (!response.ok) {
        await response.body?.cancel();
        throw rejectedError(response.status);
    }
    try {
        return await response.json();
    }
    catch {
        throw storageError('Private release metadata is invalid.');
    }
}

function findAsset(release, name) {
    const asset = Array.isArray(release.assets) ? release.assets.find((candidate) => candidate?.name === name) : null;
    if (!asset || !Number.isSafeInteger(asset.id)) {
        throw storageError(`Private release asset ${name} is missing.`);
    }
    return asset;
}

async function githubAssetResponse(target, asset) {
    const authenticated = Boolean(env.GITHUB_RELEASES_TOKEN);
    const apiUrl = `${API_ORIGIN}/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repository)}/releases/assets/${asset.id}`;
    const publicUrl = asset.browser_download_url;
    if (!authenticated && !isAllowedPublicAssetUrl(publicUrl, target, asset.name)) {
        throw storageError('Encrypted release storage returned an unsafe download location.');
    }
    let response;
    try {
        response = await fetch(authenticated ? apiUrl : publicUrl, {
            headers: authenticated ? githubHeaders('application/octet-stream') : githubHeaders(),
            redirect: 'manual'
        });
    }
    catch {
        throw unavailableError();
    }
    if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (!location || !isAllowedAssetUrl(location)) {
            throw storageError('Private release storage returned an unsafe download location.');
        }
        try {
            response = await fetch(location, { redirect: 'error' });
        }
        catch {
            throw unavailableError();
        }
    }
    if (!response.ok || !response.body) {
        await response.body?.cancel();
        throw rejectedError(response.status);
    }
    return response;
}

function githubHeaders(accept = 'application/vnd.github+json') {
    const headers = {
        accept,
        'user-agent': 'ProVisuals-Release-Gateway/1.0',
        'x-github-api-version': '2022-11-28'
    };
    if (env.GITHUB_RELEASES_TOKEN) {
        headers.authorization = `Bearer ${env.GITHUB_RELEASES_TOKEN}`;
    }
    return headers;
}

function isAllowedPublicAssetUrl(value, target, assetName) {
    try {
        const url = new URL(value);
        const expectedPath = `/${target.owner}/${target.repository}/releases/download/${target.tag}/${assetName}`;
        return url.protocol === 'https:' && url.hostname === 'github.com' && url.pathname === expectedPath;
    }
    catch {
        return false;
    }
}

function isAllowedAssetUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'https:' && (url.hostname === 'githubusercontent.com' || url.hostname.endsWith('.githubusercontent.com'));
    }
    catch {
        return false;
    }
}

async function readSmallText(response, limit) {
    const declared = Number(response.headers.get('content-length') ?? 0);
    if (declared > limit) {
        await response.body?.cancel();
        throw storageError('Private release manifest is too large.');
    }
    const chunks = [];
    let received = 0;
    for await (const chunk of Readable.fromWeb(response.body)) {
        received += chunk.length;
        if (received > limit) {
            throw storageError('Private release manifest is too large.');
        }
        chunks.push(chunk);
    }
    return Buffer.concat(chunks, received).toString('utf8');
}

function parseManifest(text) {
    let value;
    try {
        value = JSON.parse(text);
    }
    catch {
        throw storageError('Private release manifest is not valid JSON.');
    }
    if (!value || ![1, 2].includes(value.schemaVersion) || !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes <= 0 || typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256.toLowerCase()) || !Array.isArray(value.parts) || value.parts.length < 1 || value.parts.length > MAX_PARTS) {
        throw storageError('Private release manifest is invalid.');
    }
    if (value.schemaVersion === 2 && value.encryption?.algorithm !== 'aes-256-gcm') {
        throw storageError('Private release manifest uses an unsupported encryption method.');
    }
    const seen = new Set();
    for (const part of value.parts) {
        if (!part || typeof part.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(part.name) || seen.has(part.name) || !Number.isSafeInteger(part.sizeBytes) || part.sizeBytes <= 0 || typeof part.sha256 !== 'string' || !SHA256_PATTERN.test(part.sha256.toLowerCase())) {
            throw storageError('Private release manifest contains an invalid part.');
        }
        if (value.schemaVersion === 2 && (!Number.isSafeInteger(part.plainSizeBytes) || part.plainSizeBytes <= 0 || typeof part.iv !== 'string' || !/^[a-f0-9]{24}$/i.test(part.iv) || typeof part.authTag !== 'string' || !/^[a-f0-9]{32}$/i.test(part.authTag))) {
            throw storageError('Private release manifest contains invalid encrypted part data.');
        }
        seen.add(part.name);
        part.sha256 = part.sha256.toLowerCase();
    }
    value.sha256 = value.sha256.toLowerCase();
    return value;
}

function validateManifest(manifest, expectedRelease) {
    const total = manifest.parts.reduce((sum, part) => sum + (manifest.schemaVersion === 2 ? part.plainSizeBytes : part.sizeBytes), 0);
    if (!Number.isSafeInteger(total) || total !== manifest.sizeBytes || manifest.sizeBytes !== Number(expectedRelease.sizeBytes) || manifest.sha256 !== expectedRelease.sha256.toLowerCase()) {
        throw storageError('Private release manifest does not match the published product release.');
    }
    if (manifest.schemaVersion !== 2 && !env.GITHUB_RELEASES_TOKEN) {
        throw storageError('Public release assets must be encrypted.');
    }
}

async function* streamParts(target, parts, manifest) {
    const key = manifest.schemaVersion === 2 ? decryptionKey() : null;
    const expectedSize = manifest.sizeBytes;
    const outputHash = createHash('sha256');
    let total = 0;
    for (const part of parts) {
        const response = await githubAssetResponse(target, part.asset);
        const declared = Number(response.headers.get('content-length') ?? 0);
        if (declared && declared !== part.sizeBytes) {
            await response.body.cancel();
            throw storageError(`Private release part ${part.name} has an unexpected download size.`);
        }
        const hash = createHash('sha256');
        const decipher = key ? createDecipheriv('aes-256-gcm', key, Buffer.from(part.iv, 'hex')) : null;
        if (decipher) decipher.setAuthTag(Buffer.from(part.authTag, 'hex'));
        let received = 0;
        let plainReceived = 0;
        for await (const chunk of Readable.fromWeb(response.body)) {
            received += chunk.length;
            if (received > part.sizeBytes) {
                throw storageError(`Private release part ${part.name} exceeded its declared size.`);
            }
            hash.update(chunk);
            const output = decipher ? decipher.update(chunk) : chunk;
            plainReceived += output.length;
            total += output.length;
            if (total > expectedSize) throw storageError('Private release exceeded its declared size.');
            outputHash.update(output);
            if (output.length) yield output;
        }
        if (received !== part.sizeBytes || hash.digest('hex') !== part.sha256) {
            throw storageError(`Private release part ${part.name} failed verification.`);
        }
        if (decipher) {
            let final;
            try {
                final = decipher.final();
            }
            catch {
                throw storageError(`Private release part ${part.name} failed authentication.`);
            }
            plainReceived += final.length;
            total += final.length;
            outputHash.update(final);
            if (final.length) yield final;
            if (plainReceived !== part.plainSizeBytes) {
                throw storageError(`Private release part ${part.name} has an unexpected decrypted size.`);
            }
        }
    }
    if (total !== expectedSize || outputHash.digest('hex') !== manifest.sha256) {
        throw storageError('Private release download ended before all bytes were received.');
    }
}

function decryptionKey() {
    let encodedKey = env.GITHUB_RELEASES_DECRYPTION_KEY;
    if (!encodedKey) {
        try {
            encodedKey = readFileSync('/home/container/.decryption-key', 'utf8').trim();
        }
        catch {
            encodedKey = '';
        }
    }
    if (!encodedKey) {
        throw new AppError('Encrypted release storage is not configured.', 'PRIVATE_STORAGE_UNAVAILABLE', 503);
    }
    const key = Buffer.from(encodedKey, 'base64');
    if (key.length !== 32 || key.toString('base64') !== encodedKey) {
        throw storageError('The encrypted release key is invalid.');
    }
    return key;
}

function unavailableError() {
    return new AppError('Private release storage is temporarily unavailable.', 'RELEASE_HOST_UNAVAILABLE', 503);
}

function rejectedError(status) {
    return new AppError(`Private release storage rejected the request (${status}).`, 'RELEASE_HOST_ERROR', 502);
}

function storageError(message) {
    return new AppError(message, 'INVALID_RELEASE_REFERENCE', 500, false);
}
