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

const id =
  '11111111-1111-4111-8111-111111111111';

const userId =
  '22222222-2222-4222-8222-222222222222';

const secret = 'refresh-session-test-secret';

const token = id + '.' + 'A'.repeat(43);

const hash = createHmac('sha256', secret)
  .update('ted:refresh:' + token)
  .digest('hex');

function setup() {
  const session = {
    id,
    userId,
    sessionVersion: 3,
    tokenHash: hash,
    expiresAt: new Date(
      Date.now() + 3600000,
    ),
    absoluteExpiresAt: new Date(
      Date.now() + 86400000,
    ),
    revokedAt: null,
    user: {
      id: userId,
      isActive: true,
      passwordHash: null,
      emailVerifiedAt: new Date(),
      sessionVersion: 3,
    },
  };

  const prisma = {
    authSession: {
      create: vi.fn().mockResolvedValue(session),
      findUnique: vi.fn().mockResolvedValue(session),
      updateMany: vi.fn().mockResolvedValue({
        count: 1,
      }),
      deleteMany: vi.fn().mockResolvedValue({
        count: 1,
      }),
    },
    usedRefreshToken: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    $transaction: vi.fn(
      async (
        fn: (tx: unknown) => Promise<unknown>,
      ) =>
        fn({
          authSession: {
            updateMany: vi.fn().mockResolvedValue({
              count: 1,
            }),
          },
          usedRefreshToken: {
            create: vi.fn().mockResolvedValue({}),
          },
        }),
    ),
  };

  const jwt = {
    signAsync: vi.fn().mockResolvedValue(
      'signed-access-token',
    ),
  };

  const config = {
    getOrThrow: vi.fn().mockReturnValue(secret),
  };

  const service = new AuthSessionService(
    prisma as never,
    jwt as never,
    config as never,
  );

  return { service, prisma, jwt };
}

describe('Refresh token sessions', () => {
  it('creates a server-side session', async () => {
    const { service, prisma, jwt } = setup();

    const result = await service.issue(userId, 3);

    expect(result.refreshToken).toMatch(
      /^[0-9a-f-]+\.[A-Za-z0-9_-]{43}$/,
    );

    expect(
      prisma.authSession.create,
    ).toHaveBeenCalledTimes(1);

    expect(jwt.signAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: userId,
        purpose: 'access',
        sv: 3,
        sid: expect.any(String),
      }),
    );
  });

  it('rotates a refresh token', async () => {
    const { service, prisma } = setup();

    const result =
      await service.refresh(token);

    expect(result.accessToken).toBe(
      'signed-access-token',
    );

    expect(result.refreshToken).not.toBe(
      token,
    );

    expect(
      prisma.$transaction,
    ).toHaveBeenCalledTimes(1);
  });

  it('revokes a replayed token', async () => {
    const { service, prisma } = setup();

    const original =
      await prisma.authSession.findUnique();

    prisma.authSession.findUnique
      .mockResolvedValueOnce({
        ...original,
        tokenHash: 'b'.repeat(64),
      });

    prisma.usedRefreshToken.findUnique
      .mockResolvedValue({
        sessionId: id,
      });

    await expect(
      service.refresh(token),
    ).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledTimes(1);
  });

  it('revokes the current session', async () => {
    const { service, prisma } = setup();

    await service.logout(token);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id,
          tokenHash: hash,
        }),
      }),
    );
  });

  it('revokes all user sessions', async () => {
    const { service, prisma } = setup();

    await service.logoutAll(userId);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          userId,
          revokedAt: null,
        },
      }),
    );
  });
});
