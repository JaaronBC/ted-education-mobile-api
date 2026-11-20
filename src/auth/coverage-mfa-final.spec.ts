import { describe, expect, it, vi } from 'vitest';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { MfaController } from './mfa.controller';

const UID = '11111111-1111-4111-8111-111111111111';

function harness() {
  const prisma = {
    mfaSetting: {
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const config = {
    getOrThrow: vi.fn().mockReturnValue('a'.repeat(64)),
  };
  const service = new MfaService(
    prisma as never,
    {} as never,
    config as never,
    {} as never,
  );
  const auth = vi.spyOn(
    service as unknown as {
      authenticateFactor(id: string, code: string): Promise<void>;
    },
    'authenticateFactor',
  ).mockResolvedValue(undefined);
  return { service, prisma, auth };
}

describe('MFA recovery code regeneration', () => {
  it('rejects backup codes, malformed codes and non-6-digit TOTP strings', async () => {
    const h = harness();
    for (const invalid of ['AABBCCDD-11223344', '12345', '1234567', 'abc123']) {
      await expect(h.service.regenerateRecoveryCodes(UID, invalid))
        .rejects.toBeInstanceOf(BadRequestException);
    }
    expect(h.auth).not.toHaveBeenCalled();
    expect(h.prisma.mfaSetting.updateMany).not.toHaveBeenCalled();
  });

  it('does not regenerate if the supplied authenticator code is invalid or replayed', async () => {
    const h = harness();
    const failure = new Error('invalid authenticator factor');
    h.auth.mockRejectedValue(failure);
    await expect(h.service.regenerateRecoveryCodes(UID, '123456'))
      .rejects.toBe(failure);
    expect(h.prisma.mfaSetting.updateMany).not.toHaveBeenCalled();
  });

  it('atomically replaces the old hashes and returns eight unique one-time codes', async () => {
    const h = harness();
    const result = await h.service.regenerateRecoveryCodes(UID, '123456');
    expect(h.auth).toHaveBeenCalledWith(UID, '123456');
    expect(result.recoveryCodes).toHaveLength(8);
    expect(new Set(result.recoveryCodes).size).toBe(8);
    for (const code of result.recoveryCodes) {
      expect(code).toMatch(/^[A-F0-9]{8}-[A-F0-9]{8}$/);
    }
    expect(result.recoveryCodesRemaining).toBe(8);
    const update = h.prisma.mfaSetting.updateMany.mock.calls[0][0];
    expect(update.where).toEqual({ userId: UID, enabledAt: { not: null } });
    expect(update.data.recoveryHashes).toHaveLength(8);
    expect(update.data.recoveryHashes.every((x: string) => /^[a-f0-9]{64}$/.test(x)))
      .toBe(true);
    expect(update.data.recoveryHashes).not.toContain(result.recoveryCodes[0]);
  });

  it('rejects an MFA state change during regeneration', async () => {
    const h = harness();
    h.prisma.mfaSetting.updateMany.mockResolvedValue({ count: 0 });
    await expect(h.service.regenerateRecoveryCodes(UID, '123456'))
      .rejects.toBeInstanceOf(ConflictException);
  });
});

describe('MfaController regeneration route', () => {
  it('passes user and TOTP code through unchanged', async () => {
    const mfa = { regenerateRecoveryCodes: vi.fn().mockResolvedValue({ recoveryCodes: [] }) };
    const controller = new MfaController(mfa as never);
    await expect(controller.regenerateRecoveryCodes(
      { user: { id: UID, email: 'patient@example.com' } },
      { code: '123456' },
    )).resolves.toEqual({ recoveryCodes: [] });
    expect(mfa.regenerateRecoveryCodes).toHaveBeenCalledWith(UID, '123456');
  });
});
