import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException, ConflictException, UnauthorizedException,
} from '@nestjs/common';
import { compare, hash } from 'bcryptjs';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

const UID = '11111111-1111-4111-8111-111111111111';
const OLD = 'ExistingPassword123!';
const NEXT = 'CompletelyNewPassword456!';
let oldHash: string;

beforeAll(async () => {
  oldHash = await hash(OLD, 4);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function harness() {
  const user = {
    id: UID,
    email: 'patient@example.com',
    isActive: true,
    passwordHash: oldHash,
  };
  const tx = {
    user: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    authSession: { updateMany: vi.fn().mockResolvedValue({ count: 2 }) },
  };
  const prisma = {
    user: { findUnique: vi.fn().mockResolvedValue(user) },
    $transaction: vi.fn(async (callback: (client: typeof tx) => Promise<unknown>) => callback(tx)),
  };
  const settings: Record<string, string | undefined> = {};
  const config = {
    get: vi.fn((key: string) => settings[key]),
  };
  const service = new AuthService(
    prisma as never,
    {} as never,
    {} as never,
    config as never,
  );
  return { service, prisma, tx, config, settings, user };
}

describe('Change password: all observable success and failure paths', () => {
  it.each([
    ['too short', 'short'],
    ['more than 72 UTF-8 bytes', '界'.repeat(25)],
  ])('rejects a %s new password before querying the user', async (_label, newPassword) => {
    const h = harness();
    await expect(h.service.changePassword(UID, OLD, newPassword))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('rejects an account that no longer exists', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue(null);
    await expect(h.service.changePassword(UID, OLD, NEXT))
      .rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects a disabled account', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ ...h.user, isActive: false });
    await expect(h.service.changePassword(UID, OLD, NEXT))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an OAuth-only account without a password', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ ...h.user, passwordHash: null });
    await expect(h.service.changePassword(UID, OLD, NEXT))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects the wrong current password', async () => {
    const h = harness();
    await expect(h.service.changePassword(UID, 'WrongPassword123!', NEXT))
      .rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects password reuse even if the caller knows the current password', async () => {
    const h = harness();
    await expect(h.service.changePassword(UID, OLD, OLD))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('refuses a stale concurrent account update', async () => {
    const h = harness();
    h.tx.user.updateMany.mockResolvedValue({ count: 0 });
    await expect(h.service.changePassword(UID, OLD, NEXT))
      .rejects.toBeInstanceOf(ConflictException);
    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it('propagates session revocation errors instead of claiming success', async () => {
    const h = harness();
    h.tx.authSession.updateMany.mockRejectedValue(new Error('transaction aborted'));
    await expect(h.service.changePassword(UID, OLD, NEXT))
      .rejects.toThrow('transaction aborted');
  });

  it('hashes the new password and revokes existing sessions in one transaction', async () => {
    const h = harness();
    const result = await h.service.changePassword(UID, OLD, NEXT);
    expect(result.message).toContain('sessions have been revoked');
    expect(h.prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(h.tx.user.updateMany).toHaveBeenCalledWith({
      where: { id: UID, passwordHash: oldHash, isActive: true },
      data: {
        passwordHash: expect.any(String),
        sessionVersion: { increment: 1 },
      },
    });
    const saved = h.tx.user.updateMany.mock.calls[0][0].data.passwordHash as string;
    expect(saved).not.toBe(oldHash);
    expect(await compare(NEXT, saved)).toBe(true);
    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith({
      where: { userId: UID, revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it('does not email when only the API key is set', async () => {
    const h = harness();
    h.settings.RESEND_API_KEY = 'test-key';
    const mockedFetch = vi.fn();
    vi.stubGlobal('fetch', mockedFetch);
    await h.service.changePassword(UID, OLD, NEXT);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it('does not email when only the sender address is set', async () => {
    const h = harness();
    h.settings.RESET_EMAIL_FROM = 'support@example.com';
    const mockedFetch = vi.fn();
    vi.stubGlobal('fetch', mockedFetch);
    await h.service.changePassword(UID, OLD, NEXT);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it('sends a best-effort notification using trimmed configuration', async () => {
    const h = harness();
    h.settings.RESEND_API_KEY = '  key  ';
    h.settings.RESET_EMAIL_FROM = '  support@example.com  ';
    const mockedFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockedFetch);
    await h.service.changePassword(UID, OLD, NEXT);
    expect(mockedFetch).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Bearer key' }),
      }),
    );
    const sent = JSON.parse(mockedFetch.mock.calls[0][1].body as string);
    expect(sent.to).toEqual([h.user.email]);
    expect(sent.from).toBe('support@example.com');
  });

  it('does not revert a password change when the mail provider returns an error', async () => {
    const h = harness();
    h.settings.RESEND_API_KEY = 'key';
    h.settings.RESET_EMAIL_FROM = 'support@example.com';
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    await expect(h.service.changePassword(UID, OLD, NEXT)).resolves.toMatchObject({
      message: expect.stringContaining('Password changed'),
    });
    expect(warn).toHaveBeenCalled();
    expect(h.tx.authSession.updateMany).toHaveBeenCalled();
  });

  it('does not revert a password change when mail delivery throws', async () => {
    const h = harness();
    h.settings.RESEND_API_KEY = 'key';
    h.settings.RESET_EMAIL_FROM = 'support@example.com';
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('SMTP unavailable')));
    await expect(h.service.changePassword(UID, OLD, NEXT)).resolves.toMatchObject({
      message: expect.stringContaining('Password changed'),
    });
    expect(warn).toHaveBeenCalled();
  });
});

describe('AuthController change-password route', () => {
  it('delegates the signed-in user ID and both password fields', async () => {
    const auth = {
      changePassword: vi.fn().mockResolvedValue({ message: 'done' }),
    };
    const controller = new AuthController(
      auth as never, {} as never, {} as never, {} as never,
    );
    await expect(controller.changePassword(
      { user: { id: UID } },
      { currentPassword: OLD, newPassword: NEXT },
    )).resolves.toEqual({ message: 'done' });
    expect(auth.changePassword).toHaveBeenCalledWith(UID, OLD, NEXT);
  });
});
