import {
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

import { PrismaService } from '../prisma/prisma.service';
import { JWT_ACCESS_SECONDS } from './jwt.config';

const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
const UUID_TOKEN =
  /^([0-9a-f]{8}-[0-9a-f-]{27,})\.([A-Za-z0-9_-]{43})$/i;

const DENIED = 'Session expired or revoked. Sign in again.';

@Injectable()
export class AuthSessionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private digest(value: string): string {
    const secret = this.config.getOrThrow<string>(
      'REFRESH_TOKEN_SECRET',
    );

    return createHmac('sha256', secret)
      .update('ted:refresh:' + value)
      .digest('hex');
  }

  private newToken(id: string) {
    const token =
      id + '.' + randomBytes(32).toString('base64url');

    return {
      refreshToken: token,
      tokenHash: this.digest(token),
    };
  }

  private tokenId(token: string): string {
    const match = UUID_TOKEN.exec(token);

    if (!match) {
      throw new UnauthorizedException(DENIED);
    }

    return match[1];
  }

  private hashEquals(a: string, b: string) {
    if (
      !/^[0-9a-f]{64}$/i.test(a) ||
      !/^[0-9a-f]{64}$/i.test(b)
    ) {
      return false;
    }

    return timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex'),
    );
  }

  private async access(
    userId: string,
    sessionId: string,
    version: number,
    refreshToken: string,
  ) {
    const accessToken = await this.jwt.signAsync({
      sub: userId,
      sid: sessionId,
      purpose: 'access',
      sv: version,
    });

    return {
      mfaRequired: false as const,
      accessToken,
      refreshToken,
      tokenType: 'Bearer' as const,
      expiresIn: JWT_ACCESS_SECONDS,
    };
  }

  async issue(userId: string, version: number) {
    const id = randomUUID();
    const now = Date.now();
    const token = this.newToken(id);

    await this.prisma.authSession.create({
      data: {
        id,
        userId,
        sessionVersion: version,
        tokenHash: token.tokenHash,
        expiresAt: new Date(now + SEVEN_DAYS),
        absoluteExpiresAt: new Date(now + THIRTY_DAYS),
      },
    });

    try {
      return await this.access(
        userId,
        id,
        version,
        token.refreshToken,
      );
    } catch (error) {
      await this.prisma.authSession.deleteMany({
        where: { id },
      });

      throw error;
    }
  }


  private async rejectReplayedToken(
    id: string,
    oldHash: string,
    now: Date,
  ): Promise<void> {
    const used =
      await this.prisma.usedRefreshToken.findUnique({
        where: { tokenHash: oldHash },
        select: {
          sessionId: true,
          usedAt: true,
        },
      });

    if (!used || used.sessionId !== id) {
      return;
    }

    // Every consumed token is rejected.
    // Recent duplicate requests are rejected without
    // automatically declaring the session compromised.
    const age = used.usedAt
      ? now.getTime() - used.usedAt.getTime()
      : Number.POSITIVE_INFINITY;

    if (age >= 10000 || age < 0) {
      await this.prisma.authSession.updateMany({
        where: {
          id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });
    }
  }

  async refresh(refreshToken: string) {
    const id = this.tokenId(refreshToken);
    const oldHash = this.digest(refreshToken);
    const now = new Date();

    const session =
      await this.prisma.authSession.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              isActive: true,
              passwordHash: true,
              emailVerifiedAt: true,
              sessionVersion: true,
            },
          },
        },
      });

    if (
      !session ||
      session.revokedAt ||
      session.expiresAt <= now ||
      session.absoluteExpiresAt <= now ||
      !session.user.isActive ||
      session.user.sessionVersion !== session.sessionVersion ||
      (session.user.passwordHash &&
        !session.user.emailVerifiedAt)
    ) {
      throw new UnauthorizedException(DENIED);
    }

    if (!this.hashEquals(session.tokenHash, oldHash)) {
      await this.rejectReplayedToken(id, oldHash, now);
      throw new UnauthorizedException(DENIED);
    }

    const next = this.newToken(id);

    const expiry = new Date(
      Math.min(
        now.getTime() + SEVEN_DAYS,
        session.absoluteExpiresAt.getTime(),
      ),
    );

    try {
      await this.prisma.$transaction(async tx => {
        const changed =
          await tx.authSession.updateMany({
            where: {
              id,
              tokenHash: oldHash,
              revokedAt: null,
              expiresAt: { gt: now },
              absoluteExpiresAt: { gt: now },
            },
            data: {
              tokenHash: next.tokenHash,
              expiresAt: expiry,
            },
          });

        if (changed.count !== 1) {
          throw new UnauthorizedException(DENIED);
        }

        await tx.usedRefreshToken.create({
          data: {
            tokenHash: oldHash,
            sessionId: id,
          },
        });
      });
    } catch (error) {
      await this.rejectReplayedToken(
        id,
        oldHash,
        new Date(),
      );

      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException(DENIED);
    }
    return this.access(
      session.userId,
      id,
      session.sessionVersion,
      next.refreshToken,
    );
  }

  async logout(refreshToken: string) {
    const id = this.tokenId(refreshToken);
    const hash = this.digest(refreshToken);

    await this.prisma.authSession.updateMany({
      where: {
        id,
        tokenHash: hash,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });

    return { message: 'Signed out.' };
  }


  async logoutCurrent(
    userId: string,
    sessionId: string,
  ) {
    await this.prisma.authSession.updateMany({
      where: {
        id: sessionId,
        userId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return { message: 'Signed out.' };
  }

  async logoutAll(userId: string) {
    await this.prisma.authSession.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });

    return { message: 'All sessions revoked.' };
  }
}
