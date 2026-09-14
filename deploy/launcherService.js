import { createReadStream, existsSync } from 'node:fs';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { AuditAction, LicenseStatus, ProductStatus } from '@prisma/client';
import { env } from '../config/env.js';
import { createDeviceDigest, createHmacDigest, createLicenseLookupDigest } from '../security/keys.js';
import { AppError, ForbiddenError, NotFoundError, UnauthorizedError } from '../utils/errors.js';
import { KeyedMutex } from '../utils/keyedMutex.js';
import { githubReleaseStream } from './githubReleaseStorage.js';
const licenseInclude = {
    product: {
        include: {
            releases: {
                where: { published: true },
                orderBy: { createdAt: 'desc' },
                take: 1
            }
        }
    },
    launcherDeviceBinding: true
};
export class LauncherService {
    prisma;
    auditService;
    discordClient;
    criticalSections = new KeyedMutex();
    constructor(prisma, auditService, discordClient) {
        this.prisma = prisma;
        this.auditService = auditService;
        this.discordClient = discordClient;
    }
    async hasLauncherRole(discordUserId) {
        const member = await this.fetchMember(discordUserId);
        return this.memberHasLauncherRole(member);
    }
    async issueTicket(discordUserId, purpose) {
        await this.requireMember(discordUserId);
        if (purpose === 'LOGIN') {
            await this.requireOwnedLicense(discordUserId);
        }
        const token = randomToken();
        await this.prisma.launcherLoginTicket.create({
            data: {
                tokenDigest: ticketDigest(token),
                discordUserId,
                purpose,
                expiresAt: new Date(Date.now() + env.LAUNCHER_LOGIN_TICKET_TTL_SECONDS * 1000)
            }
        });
        return token;
    }
    async licenseSummary(discordUserId) {
        await this.requireMember(discordUserId);
        const license = await this.requireOwnedLicense(discordUserId);
        return {
            productName: license.product.name,
            keyDisplay: license.keyDisplay,
            status: license.status,
            expiresAt: license.expiresAt,
            deviceLabel: license.launcherDeviceBinding?.deviceLabel ?? null,
            hasRelease: license.product.releases.length > 0
        };
    }
    async exchange(ticket, device) {
        const discordUserId = await this.consumeTicket(ticket, 'LOGIN');
        const member = await this.requireMember(discordUserId);
        const licenses = await this.requireOwnedLicenses(discordUserId);
        const license = licenses[0];
        const boundLicense = await this.bindOrRevoke(license, discordUserId, device);
        const token = randomToken();
        await this.prisma.launcherSession.create({
            data: {
                tokenDigest: sessionDigest(token),
                discordUserId,
                licenseId: boundLicense.id,
                deviceDigest: createDeviceDigest(device.id, env.DEVICE_HASH_SECRET),
                deviceLabel: device.label,
                expiresAt: new Date(Date.now() + env.LAUNCHER_SESSION_TTL_HOURS * 60 * 60 * 1000)
            }
        });
        await this.auditService.record({
            action: AuditAction.LAUNCHER_SIGN_IN,
            licenseId: boundLicense.id,
            productId: boundLicense.productId,
            actorDiscordId: discordUserId,
            targetDiscordId: discordUserId,
            licenseKeyDisplay: boundLicense.keyDisplay,
            metadata: { deviceLabel: device.label, appVersion: device.appVersion }
        });
        const accountLicenses = licenses.map((candidate) => candidate.id === boundLicense.id ? boundLicense : candidate);
        return { token, account: this.serializeAccount(member, boundLicense, accountLicenses) };
    }
    async accountForSession(token, deviceId) {
        const session = await this.prisma.launcherSession.findUnique({
            where: { tokenDigest: sessionDigest(token) }
        });
        if (!session || session.revokedAt || session.expiresAt <= new Date()) {
            throw new UnauthorizedError('Your launcher session has expired. Sign in through Discord again.');
        }
        const requestDeviceDigest = createDeviceDigest(deviceId, env.DEVICE_HASH_SECRET);
        if (requestDeviceDigest !== session.deviceDigest) {
            await this.revokeSession(session.id);
            throw new ForbiddenError('This launcher session belongs to another device.');
        }
        const member = await this.requireMember(session.discordUserId);
        const license = session.licenseId
            ? await this.prisma.userLicense.findUnique({
                where: { id: session.licenseId },
                include: licenseInclude
            })
            : null;
        if (!license || license.ownerDiscordId !== session.discordUserId) {
            await this.revokeSession(session.id);
            throw new ForbiddenError('The license is no longer connected to this Discord account.');
        }
        this.requireActiveLicense(license);
        if (license.launcherDeviceBinding?.deviceDigest !== session.deviceDigest) {
            await this.revokeSession(session.id);
            throw new ForbiddenError('This device is no longer registered to the license.');
        }
        await this.prisma.launcherSession.update({
            where: { id: session.id },
            data: { lastSeenAt: new Date() }
        });
        const licenses = await this.requireOwnedLicenses(session.discordUserId);
        return {
            sessionId: session.id,
            session,
            account: this.serializeAccount(member, license, licenses),
            license,
            licenses
        };
    }
    async logout(token) {
        const session = await this.prisma.launcherSession.findUnique({
            where: { tokenDigest: sessionDigest(token) }
        });
        if (!session)
            return;
        await this.revokeSession(session.id);
        await this.auditService.record({
            action: AuditAction.LAUNCHER_SIGN_OUT,
            licenseId: session.licenseId,
            actorDiscordId: session.discordUserId,
            targetDiscordId: session.discordUserId
        });
    }
    async activate(token, device, licenseKey) {
        const context = await this.accountForSession(token, device.id);
        const matching = await this.prisma.userLicense.findUnique({
            where: { keyLookupDigest: createLicenseLookupDigest(licenseKey, env.LICENSE_LOOKUP_SECRET) },
            include: licenseInclude
        });
        if (!matching)
            throw new NotFoundError('That license key is not valid.');
        if (matching.ownerDiscordId !== context.license.ownerDiscordId) {
            await this.revokeForDuplicate(matching, context.license.ownerDiscordId, 'DUPLICATE_ACCOUNT');
            throw new AppError('This license belongs to a different Discord account and has been revoked.', 'DUPLICATE_ACCOUNT', 423);
        }
        const bound = await this.bindOrRevoke(matching, matching.ownerDiscordId, device);
        await this.prisma.launcherSession.update({
            where: { id: context.sessionId },
            data: { licenseId: bound.id }
        });
        const member = await this.requireMember(matching.ownerDiscordId);
        const licenses = await this.requireOwnedLicenses(matching.ownerDiscordId);
        const accountLicenses = licenses.map((candidate) => candidate.id === bound.id ? bound : candidate);
        return this.serializeAccount(member, bound, accountLicenses);
    }
    async consumeDownload(ticket) {
        const discordUserId = await this.consumeTicket(ticket, 'DOWNLOAD');
        await this.requireMember(discordUserId);
        await this.requireOwnedLicense(discordUserId);
        const release = await this.prisma.launcherRelease.findFirst({
            where: { published: true },
            orderBy: { createdAt: 'desc' }
        });
        if (!release || !existsSync(release.storagePath)) {
            throw new NotFoundError('No launcher build is published yet.');
        }
        await this.auditService.record({
            action: AuditAction.RELEASE_DOWNLOADED,
            actorDiscordId: discordUserId,
            targetDiscordId: discordUserId,
            metadata: { releaseType: 'launcher', version: release.version }
        });
        return { ...release, stream: createReadStream(release.storagePath) };
    }
    async productDownload(token, deviceId, productId) {
        const context = await this.accountForSession(token, deviceId);
        const license = context.licenses.find((candidate) => candidate.productId === productId);
        if (!license) {
            throw new ForbiddenError('Your license does not include this product.');
        }
        if (license.product.status !== ProductStatus.ACTIVE) {
            throw new ForbiddenError('This product is currently unavailable.');
        }
        const boundLicense = await this.bindOrRevoke(license, context.license.ownerDiscordId, {
            id: deviceId,
            label: context.session.deviceLabel,
            appVersion: undefined
        });
        const release = await this.prisma.productRelease.findFirst({
            where: { productId, published: true },
            orderBy: { createdAt: 'desc' }
        });
        if (!release) {
            throw new NotFoundError('No published release is available for this product.');
        }
        let stream;
        if (release.downloadUrl) {
            stream = await remoteReleaseStream(release.downloadUrl, release);
        }
        else {
            if (!release.storagePath || !existsSync(release.storagePath)) {
                throw new NotFoundError('No published release is available for this product.');
            }
            stream = createReadStream(release.storagePath);
        }
        await this.auditService.record({
            action: AuditAction.RELEASE_DOWNLOADED,
            licenseId: boundLicense.id,
            productId,
            actorDiscordId: boundLicense.ownerDiscordId,
            targetDiscordId: boundLicense.ownerDiscordId,
            licenseKeyDisplay: boundLicense.keyDisplay,
            metadata: { releaseType: 'product', version: release.version }
        });
        return { ...release, stream };
    }
    async issueRuntimeEntitlement(token, deviceId, productId, runtimeDeviceId) {
        const context = await this.accountForSession(token, deviceId);
        const license = context.licenses.find((candidate) => candidate.productId === productId);
        if (!license) {
            throw new ForbiddenError('Your license does not include this product.');
        }
        if (license.product.status !== ProductStatus.ACTIVE) {
            throw new ForbiddenError('This product is currently unavailable.');
        }
        const boundLicense = await this.bindOrRevoke(license, context.license.ownerDiscordId, {
            id: deviceId,
            label: context.session.deviceLabel,
            appVersion: undefined
        });
        const purpose = runtimePurpose(boundLicense.id, productId);
        return this.criticalSections.runExclusive(`runtime-license:${boundLicense.id}`, async () => {
            const runtimeToken = `PVR-${randomToken()}`;
            const now = new Date();
            const maxExpiry = new Date(now.getTime() + 180 * 24 * 60 * 60 * 1000);
            const expiresAt = boundLicense.expiresAt && boundLicense.expiresAt < maxExpiry
                ? boundLicense.expiresAt
                : maxExpiry;
            const runtimeDeviceDigest = createDeviceDigest(runtimeDeviceId, env.DEVICE_HASH_SECRET);
            const registeredDevices = await this.prisma.licenseDevice.findMany({
                where: { licenseId: boundLicense.id },
                orderBy: { firstSeenAt: 'asc' }
            });
            const registeredDevice = registeredDevices.find((device) => device.deviceDigest === runtimeDeviceDigest);
            if (!registeredDevice && registeredDevices.length > 0) {
                await this.prisma.launcherLoginTicket.updateMany({
                    where: { discordUserId: boundLicense.ownerDiscordId, purpose, consumedAt: null },
                    data: { consumedAt: now }
                });
                await this.auditService.record({
                    action: AuditAction.VALIDATION_SUSPICIOUS,
                    licenseId: boundLicense.id,
                    productId,
                    actorDiscordId: boundLicense.ownerDiscordId,
                    targetDiscordId: boundLicense.ownerDiscordId,
                    licenseKeyDisplay: boundLicense.keyDisplay,
                    reason: 'Launcher attempted to authorize a different runtime device.',
                    metadata: { reasonCode: 'DEVICE_MISMATCH' }
                });
                throw new AppError('This license is registered to another runtime device. Reset the device from the admin panel before repairing.', 'DEVICE_MISMATCH', 423);
            }
            await this.prisma.$transaction(async (tx) => {
                if (registeredDevice) {
                    await tx.licenseDevice.update({
                        where: { id: registeredDevice.id },
                        data: {
                            lastSeenAt: now,
                            lastDiscordUserId: boundLicense.ownerDiscordId
                        }
                    });
                }
                else {
                    await tx.licenseDevice.create({
                        data: {
                            licenseId: boundLicense.id,
                            deviceDigest: runtimeDeviceDigest,
                            deviceDisplay: `${runtimeDeviceDigest.slice(0, 8)}...${runtimeDeviceDigest.slice(-8)}`,
                            lastDiscordUserId: boundLicense.ownerDiscordId,
                            validationCount: 0
                        }
                    });
                }
                await tx.launcherLoginTicket.updateMany({
                    where: {
                        discordUserId: boundLicense.ownerDiscordId,
                        purpose,
                        consumedAt: null
                    },
                    data: { consumedAt: now }
                });
                await tx.launcherLoginTicket.create({
                    data: {
                        tokenDigest: runtimeDigest(runtimeToken),
                        discordUserId: boundLicense.ownerDiscordId,
                        purpose,
                        expiresAt
                    }
                });
            });
            return {
                token: runtimeToken,
                productCode: boundLicense.product.code,
                endpoint: `${env.PUBLIC_BASE_URL.replace(/\/$/, '')}/api/v1/licenses/runtime`,
                expiresAt: expiresAt.toISOString(),
                nextValidationSeconds: env.LICENSE_RECHECK_SECONDS
            };
        });
    }
    async validateRuntimeEntitlement(entitlementToken, deviceId, productCode, appVersion) {
        if (entitlementToken.length < 40 || entitlementToken.length > 256) {
            throw new UnauthorizedError('This runtime entitlement is invalid.');
        }
        const grant = await this.prisma.launcherLoginTicket.findUnique({
            where: { tokenDigest: runtimeDigest(entitlementToken) }
        });
        if (!grant || grant.consumedAt || grant.expiresAt <= new Date()) {
            throw new AppError('This runtime entitlement is expired or revoked. Repair the product in the ProVisuals Launcher.', 'ENTITLEMENT_REVOKED', 423);
        }
        const parsedPurpose = parseRuntimePurpose(grant.purpose);
        if (!parsedPurpose) {
            throw new UnauthorizedError('This runtime entitlement is invalid.');
        }
        const license = await this.prisma.userLicense.findUnique({
            where: { id: parsedPurpose.licenseId },
            include: {
                product: true,
                devices: { orderBy: { firstSeenAt: 'asc' } },
                launcherDeviceBinding: true
            }
        });
        if (!license || license.ownerDiscordId !== grant.discordUserId || license.productId !== parsedPurpose.productId) {
            await this.revokeRuntimeGrant(grant.id);
            throw new AppError('This runtime entitlement is no longer connected to a license.', 'ENTITLEMENT_REVOKED', 423);
        }
        if (license.product.code.trim().toUpperCase() !== productCode.trim().toUpperCase()) {
            throw new AppError('This entitlement belongs to a different product.', 'PRODUCT_MISMATCH', 403);
        }
        if (license.product.status !== ProductStatus.ACTIVE) {
            throw new AppError('This product is disabled.', 'PRODUCT_DISABLED', 423);
        }
        if (license.status !== LicenseStatus.ACTIVE) {
            throw new AppError('This license is suspended or revoked.', license.status === LicenseStatus.REVOKED ? 'LICENSE_REVOKED' : 'LICENSE_SUSPENDED', 423);
        }
        if (license.expiresAt && license.expiresAt <= new Date()) {
            throw new AppError('This license has expired.', 'LICENSE_EXPIRED', 423);
        }
        if (!license.launcherDeviceBinding) {
            throw new AppError('This license is not registered to a launcher device.', 'DEVICE_MISMATCH', 423);
        }
        const runtimeDeviceDigest = createDeviceDigest(deviceId, env.DEVICE_HASH_SECRET);
        const existingDevice = license.devices.find((device) => device.deviceDigest === runtimeDeviceDigest);
        if (!existingDevice) {
            await this.revokeRuntimeGrant(grant.id);
            await this.auditService.record({
                action: AuditAction.VALIDATION_SUSPICIOUS,
                licenseId: license.id,
                productId: license.productId,
                actorDiscordId: license.ownerDiscordId,
                targetDiscordId: license.ownerDiscordId,
                licenseKeyDisplay: license.keyDisplay,
                reason: 'Runtime entitlement was presented from a different device.',
                metadata: { reasonCode: 'DEVICE_MISMATCH', appVersion }
            });
            throw new AppError('This copy is registered to another device. Open the ProVisuals Launcher and repair the product to re-authorize it.', 'DEVICE_MISMATCH', 423);
        }
        await this.prisma.licenseDevice.update({
            where: { id: existingDevice.id },
            data: {
                lastSeenAt: new Date(),
                lastAppVersion: appVersion,
                lastDiscordUserId: license.ownerDiscordId,
                validationCount: { increment: 1 }
            }
        });
        return {
            valid: true,
            code: 'LICENSE_VALID',
            message: 'Runtime entitlement is active.',
            data: {
                productCode: license.product.code,
                status: license.status,
                expiresAt: license.expiresAt?.toISOString() ?? null,
                deviceBound: true,
                serverTime: Math.floor(Date.now() / 1000),
                nextValidationSeconds: env.LICENSE_RECHECK_SECONDS
            }
        };
    }
    async revokeRuntimeGrant(id) {
        await this.prisma.launcherLoginTicket.updateMany({
            where: { id, consumedAt: null },
            data: { consumedAt: new Date() }
        });
    }
    async consumeTicket(token, purpose) {
        if (token.length < 32)
            throw new UnauthorizedError('This launcher ticket is invalid.');
        const ticket = await this.prisma.launcherLoginTicket.findUnique({
            where: { tokenDigest: ticketDigest(token) }
        });
        if (!ticket ||
            ticket.purpose !== purpose ||
            ticket.consumedAt ||
            ticket.expiresAt <= new Date()) {
            throw new UnauthorizedError('This launcher ticket is invalid, expired, or already used.');
        }
        const consumed = await this.prisma.launcherLoginTicket.updateMany({
            where: { id: ticket.id, consumedAt: null, expiresAt: { gt: new Date() } },
            data: { consumedAt: new Date() }
        });
        if (consumed.count !== 1) {
            throw new UnauthorizedError('This launcher ticket was already used.');
        }
        return ticket.discordUserId;
    }
    async requireMember(discordUserId) {
        const member = await this.fetchMember(discordUserId);
        if (!this.memberHasLauncherRole(member)) {
            await this.prisma.launcherSession.updateMany({
                where: { discordUserId, revokedAt: null },
                data: { revokedAt: new Date() }
            });
            throw new ForbiddenError('The required ProVisuals customer role is not active on your Discord account.');
        }
        return member;
    }
    async fetchMember(discordUserId) {
        if (!this.discordClient.isReady()) {
            throw new AppError('Discord verification is temporarily unavailable.', 'DISCORD_UNAVAILABLE', 503);
        }
        try {
            const guild = await this.discordClient.guilds.fetch(env.DISCORD_GUILD_ID);
            return await guild.members.fetch(discordUserId);
        }
        catch {
            throw new ForbiddenError('Your Discord account is not a member of the ProVisuals server.');
        }
    }
    memberHasLauncherRole(member) {
        if (member.id === member.guild.ownerId)
            return true;
        const allowed = new Set([
            ...env.DISCORD_ADMIN_ROLE_IDS,
            ...(env.DISCORD_CUSTOMER_ROLE_ID ? [env.DISCORD_CUSTOMER_ROLE_ID] : [])
        ]);
        return member.roles.cache.some((role) => allowed.has(role.id));
    }
    async requireOwnedLicense(discordUserId) {
        return (await this.requireOwnedLicenses(discordUserId))[0];
    }
    async requireOwnedLicenses(discordUserId) {
        const licenses = await this.prisma.userLicense.findMany({
            where: { ownerDiscordId: discordUserId },
            include: licenseInclude,
            orderBy: { createdAt: 'desc' }
        });
        const active = licenses.filter((license) => license.status === LicenseStatus.ACTIVE &&
            (!license.expiresAt || license.expiresAt > new Date()));
        if (!active.length) {
            throw new ForbiddenError('No active ProVisuals license is connected to your Discord account.');
        }
        return active;
    }
    requireActiveLicense(license) {
        if (license.status !== LicenseStatus.ACTIVE) {
            throw new AppError('This license is suspended or revoked.', 'LICENSE_INACTIVE', 423);
        }
        if (license.expiresAt && license.expiresAt <= new Date()) {
            throw new AppError('This license has expired.', 'LICENSE_EXPIRED', 423);
        }
    }
    async bindOrRevoke(license, discordUserId, device) {
        return this.criticalSections.runExclusive(`launcher-license:${license.id}`, async () => {
            const current = await this.prisma.userLicense.findUnique({
                where: { id: license.id },
                include: licenseInclude
            });
            if (!current)
                throw new NotFoundError('The connected license no longer exists.');
            this.requireActiveLicense(current);
            const digest = createDeviceDigest(device.id, env.DEVICE_HASH_SECRET);
            const binding = current.launcherDeviceBinding;
            if (binding && binding.deviceDigest !== digest) {
                await this.revokeForDuplicate(current, discordUserId, 'DUPLICATE_DEVICE');
                throw new AppError('This license was already registered to another PC and has been automatically revoked.', 'DUPLICATE_DEVICE', 423);
            }
            if (binding) {
                await this.prisma.launcherDeviceBinding.update({
                    where: { id: binding.id },
                    data: {
                        lastSeenAt: new Date(),
                        lastAppVersion: device.appVersion,
                        lastDiscordUserId: discordUserId,
                        deviceLabel: device.label,
                        claimCount: { increment: 1 }
                    }
                });
            }
            else {
                await this.prisma.launcherDeviceBinding.create({
                    data: {
                        licenseId: current.id,
                        deviceDigest: digest,
                        deviceLabel: device.label,
                        lastAppVersion: device.appVersion,
                        lastDiscordUserId: discordUserId
                    }
                });
            }
            return (await this.prisma.userLicense.findUnique({
                where: { id: current.id },
                include: licenseInclude
            }));
        });
    }
    async revokeForDuplicate(license, actorDiscordId, reasonCode) {
        const reason = reasonCode === 'DUPLICATE_DEVICE'
            ? 'Automatic launcher revocation: the license was used from a second device.'
            : 'Automatic launcher revocation: the license was used by a different Discord account.';
        const now = new Date();
        const audit = await this.prisma.$transaction(async (tx) => {
            await tx.userLicense.update({
                where: { id: license.id },
                data: { status: LicenseStatus.REVOKED, revokedAt: now, revokedReason: reason }
            });
            await tx.launcherSession.updateMany({
                where: { licenseId: license.id, revokedAt: null },
                data: { revokedAt: now }
            });
            return this.auditService.createDatabaseRecord({
                action: AuditAction.LAUNCHER_DUPLICATE_DEVICE,
                licenseId: license.id,
                productId: license.productId,
                actorDiscordId,
                targetDiscordId: license.ownerDiscordId,
                licenseKeyDisplay: license.keyDisplay,
                reason,
                metadata: { reasonCode }
            }, tx);
        });
        await this.auditService.sendDiscordLog(audit);
    }
    async revokeSession(sessionId) {
        await this.prisma.launcherSession.updateMany({
            where: { id: sessionId, revokedAt: null },
            data: { revokedAt: new Date() }
        });
    }
    serializeAccount(member, license, licenses = [license]) {
        const device = license.launcherDeviceBinding;
        const computedStatus = license.status === LicenseStatus.ACTIVE &&
            license.expiresAt &&
            license.expiresAt <= new Date()
            ? 'EXPIRED'
            : license.status;
        return {
            id: member.id,
            discordId: member.id,
            username: member.user.globalName ?? member.user.username,
            avatarUrl: member.user.displayAvatarURL({ extension: 'png', size: 128 }),
            roleVerifiedAt: new Date().toISOString(),
            license: {
                id: license.id,
                suffix: license.keyDisplay.slice(-6),
                label: `${license.product.name} License`,
                status: computedStatus,
                expiresAt: license.expiresAt?.toISOString() ?? null,
                deviceLabel: device?.deviceLabel ?? null,
                violationReason: license.revokedReason ?? license.suspendedReason ?? null
            },
            products: [...new Map(licenses.map((candidate) => [candidate.productId, candidate])).values()].map((candidate) => {
                const release = candidate.product.releases[0] ?? null;
                return {
                    id: candidate.product.id,
                    slug: candidate.product.code.toLowerCase().replace(/_/g, '-'),
                    name: candidate.product.name,
                    description: candidate.product.description ?? 'Licensed ProVisuals content.',
                    installTarget: 'ASSETTO_CORSA_ROOT',
                    latestVersion: release?.version ?? null,
                    releaseNotes: release?.releaseNotes ?? null,
                    downloadSize: release?.sizeBytes ?? null,
                    sha256: release?.sha256 ?? null
                };
            })
        };
    }
}
async function remoteReleaseStream(downloadUrl, release) {
    if (downloadUrl.startsWith('ghrel://')) {
        return githubReleaseStream(downloadUrl, release);
    }
    if (downloadUrl.startsWith('r2://')) {
        return privateReleaseStream(downloadUrl);
    }
    if (env.NODE_ENV === 'production') {
        throw new AppError('Public product origins are disabled. Publish this release from private storage.', 'PUBLIC_RELEASE_ORIGIN_DISABLED', 503);
    }
    let response;
    try {
        response = await fetch(downloadUrl, { redirect: 'follow' });
    }
    catch {
        throw new AppError('The product download host is temporarily unavailable.', 'RELEASE_HOST_UNAVAILABLE', 503);
    }
    if (!response.ok || !response.body) {
        throw new AppError('The product download host rejected the request.', 'RELEASE_HOST_ERROR', 502);
    }
    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    if (contentType.includes('text/html')) {
        await response.body.cancel();
        throw new AppError('The product download URL returned a web page instead of the ZIP package.', 'INVALID_RELEASE_RESPONSE', 502);
    }
    return Readable.fromWeb(response.body);
}
async function privateReleaseStream(reference) {
    if (!env.PRIVATE_RELEASES_ENDPOINT || !env.PRIVATE_RELEASES_ACCESS_KEY_ID || !env.PRIVATE_RELEASES_SECRET_ACCESS_KEY) {
        throw new AppError('Private release storage is not configured.', 'PRIVATE_STORAGE_UNAVAILABLE', 503);
    }
    let parsed;
    try {
        parsed = new URL(reference);
    }
    catch {
        throw new AppError('The private product object reference is invalid.', 'INVALID_RELEASE_REFERENCE', 500, false);
    }
    const bucket = parsed.hostname;
    const objectKey = decodeURIComponent(parsed.pathname.replace(/^\/+/, ''));
    if (!bucket || !objectKey || objectKey.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
        throw new AppError('The private product object reference is invalid.', 'INVALID_RELEASE_REFERENCE', 500, false);
    }
    const endpoint = new URL(env.PRIVATE_RELEASES_ENDPOINT);
    const canonicalPath = `/${encodeURIComponent(bucket)}/${objectKey.split('/').map(encodeURIComponent).join('/')}`;
    const target = new URL(canonicalPath, endpoint.origin);
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = 'UNSIGNED-PAYLOAD';
    const canonicalHeaders = `host:${target.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalRequest = ['GET', canonicalPath, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope = `${dateStamp}/${env.PRIVATE_RELEASES_REGION}/s3/aws4_request`;
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
    const dateKey = hmac(`AWS4${env.PRIVATE_RELEASES_SECRET_ACCESS_KEY}`, dateStamp);
    const regionKey = hmac(dateKey, env.PRIVATE_RELEASES_REGION);
    const serviceKey = hmac(regionKey, 's3');
    const signingKey = hmac(serviceKey, 'aws4_request');
    const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    const authorization = `AWS4-HMAC-SHA256 Credential=${env.PRIVATE_RELEASES_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    let response;
    try {
        response = await fetch(target, {
            headers: {
                authorization,
                'x-amz-content-sha256': payloadHash,
                'x-amz-date': amzDate
            },
            redirect: 'error'
        });
    }
    catch {
        throw new AppError('Private product storage is temporarily unavailable.', 'RELEASE_HOST_UNAVAILABLE', 503);
    }
    if (!response.ok || !response.body) {
        await response.body?.cancel();
        throw new AppError('Private product storage rejected the request.', 'RELEASE_HOST_ERROR', 502);
    }
    return Readable.fromWeb(response.body);
}
function sha256(value) {
    return createHash('sha256').update(value, 'utf8').digest('hex');
}
function hmac(key, value) {
    return createHmac('sha256', key).update(value, 'utf8').digest();
}
function randomToken() {
    return randomBytes(32).toString('base64url');
}
function ticketDigest(token) {
    return createHmacDigest(`launcher-ticket:${token}`, env.LICENSE_LOOKUP_SECRET);
}
function sessionDigest(token) {
    return createHmacDigest(`launcher-session:${token}`, env.LICENSE_LOOKUP_SECRET);
}
function runtimeDigest(token) {
    return createHmacDigest(`launcher-runtime:${token}`, env.LICENSE_LOOKUP_SECRET);
}
function runtimePurpose(licenseId, productId) {
    return `RUNTIME:${licenseId}:${productId}`;
}
function parseRuntimePurpose(purpose) {
    const match = /^RUNTIME:([0-9a-f-]{36}):([0-9a-f-]{36})$/i.exec(purpose);
    return match ? { licenseId: match[1], productId: match[2] } : null;
}
