import {
  describe,
  expect,
  it,
  vi,
} from 'vitest';

import {
  UnauthorizedException,
} from '@nestjs/common';

import { createHmac } from 'node:crypto';
import { AuthSessionService } from './auth-session.service';
import { EmailVerificationService } from './email-verification.service';

const sid =
  '11111111-1111-4111-8111-111111111111';

const uid =
  '22222222-2222-4222-8222-222222222222';

const secret = 'harden-test-secret';
const token = sid + '.' + 'A'.repeat(43);

const digest = createHmac('sha256', secret)
  .update('ted:refresh:' + token)
  .digest('hex');

function harness(usedAt: Date) {
  const prisma = {
    authSession: {
      findUnique: vi.fn().mockResolvedValue({
        id: sid,
        userId: uid,
        tokenHash: 'b'.repeat(64),
        revokedAt: null,
        expiresAt: new Date(Date.now() + 600000),
        absoluteExpiresAt: new Date(
          Date.now() + 600000,
        ),
        sessionVersion: 1,
        user: {
          isActive: true,
          passwordHash: null,
          emailVerifiedAt: null,
          sessionVersion: 1,
        },
      }),
      updateMany: vi.fn().mockResolvedValue({
        count: 1,
      }),
    },
    usedRefreshToken: {
      findUnique: vi.fn().mockResolvedValue({
        sessionId: sid,
        usedAt,
      }),
    },
  };

  const service = new AuthSessionService(
    prisma as never,
    {} as never,
    {
      getOrThrow: () => secret,
    } as never,
  );

  return { prisma, service };
}

describe('Authentication hardening', () => {
  it('rejects recent duplicate refresh without revocation', async () => {
    const { prisma, service } = harness(new Date());

    await expect(
      service.refresh(token),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(
      prisma.authSession.updateMany,
    ).not.toHaveBeenCalled();
  });

  it('revokes a session after older token replay', async () => {
    const { prisma, service } = harness(
      new Date(Date.now() - 30000),
    );

    await expect(
      service.refresh(token),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: sid,
          revokedAt: null,
        },
      }),
    );
  });

  it('revokes by user and session id', async () => {
    const { prisma, service } = harness(new Date());

    await service.logoutCurrent(uid, sid);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: sid,
          userId: uid,
          revokedAt: null,
        },
      }),
    );

    expect(digest).toHaveLength(64);
  });

  it('reserves email quota atomically', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({
          id: uid,
          isActive: true,
          passwordHash: 'hash',
          emailVerifiedAt: null,
        }),
      },
      $queryRaw: vi.fn().mockResolvedValue([]),
    };

    const service = new EmailVerificationService(
      prisma as never,
      {
        get: (key: string) =>
          key === 'RESEND_API_KEY'
            ? 'key'
            : 'from@example.com',
        getOrThrow: () => secret,
      } as never,
    );

    const result = await service.requestCode(
      ' TEST@example.com ',
    );

    expect(result.message).toContain('code');

    expect(
      prisma.$queryRaw,
    ).toHaveBeenCalledOnce();

    expect(
      prisma.user.findUnique,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          email: 'test@example.com',
        },
      }),
    );
  });
});
