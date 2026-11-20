import { describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { hash } from 'bcryptjs';

import { AuthService } from './auth.service';
import { EmailVerificationService } from './email-verification.service';

const ID = '11111111-1111-4111-8111-111111111111';
const SECRET = 'test-only-secret';

describe('Email verification', () => {
  it('blocks unverified password login', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({
          id: ID,
          isActive: true,
          emailVerifiedAt: null,
          passwordHash: await hash('CorrectPassword123!', 4),
        }),
      },
    };

    const mfa = { loginResult: vi.fn() };

    const service = new AuthService(
      prisma as never,
      {} as never,
      mfa as never
    );

    await expect(
      service.login({
        email: 'a@example.com',
        password: 'CorrectPassword123!',
      })
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(mfa.loginResult).not.toHaveBeenCalled();
  });

  it('rejects expired code', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({
          id: ID,
          isActive: true,
          passwordHash: 'hash',
          emailVerifiedAt: null,
        }),
      },
      emailVerificationCode: {
        findUnique: vi.fn().mockResolvedValue({
          codeHash: 'a'.repeat(64),
          attempts: 0,
          expiresAt: new Date(Date.now() - 1000),
        }),
      },
    };

    const service = new EmailVerificationService(
      prisma as never,
      {} as never
    );

    await expect(
      service.confirmCode('a@example.com', '12345678')
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('consumes valid code in a transaction', async () => {
    const code = '12345678';

    const codeHash = createHmac('sha256', SECRET)
      .update('ted:verify-email:' + ID + ':' + code)
      .digest('hex');

    const tx = {
      emailVerificationCode: {
        deleteMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
      user: {
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
    };

    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({
          id: ID,
          isActive: true,
          passwordHash: 'hash',
          emailVerifiedAt: null,
        }),
      },
      emailVerificationCode: {
        findUnique: vi.fn().mockResolvedValue({
          userId: ID,
          codeHash,
          attempts: 0,
          expiresAt: new Date(Date.now() + 600000),
        }),
      },
      $transaction: vi.fn(
        async (callback: (t: typeof tx) => Promise<unknown>) =>
          callback(tx)
      ),
    };

    const config = {
      getOrThrow: vi.fn().mockReturnValue(SECRET),
    };

    const service = new EmailVerificationService(
      prisma as never,
      config as never
    );

    const result = await service.confirmCode(
      'a@example.com',
      code
    );

    expect(result.message).toContain('verified');

    expect(
      tx.emailVerificationCode.deleteMany
    ).toHaveBeenCalledTimes(1);

    expect(
      tx.user.updateMany
    ).toHaveBeenCalledTimes(1);
  });
});
