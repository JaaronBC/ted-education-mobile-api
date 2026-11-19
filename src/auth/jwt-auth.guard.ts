import {
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_ALGORITHM,
} from './jwt.config';
import {
  CanActivate, ExecutionContext, Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp()
      .getRequest<Request & { user?: unknown; sessionId?: string }>();

    const [scheme, token] =
      (req.headers.authorization ?? '').split(' ');

    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException();
    }

    let payload: { sub?: string; sid?: string; purpose?: string; sv?: number };

    try {
      payload = await this.jwt.verifyAsync(token, {
        algorithms: [JWT_ALGORITHM],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (payload.purpose !== 'access' || typeof payload.sv !== 'number' || !payload.sid) {
      throw new UnauthorizedException('Full authentication required.');
    }

    if (!payload.sub ||
        !/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(payload.sub)) {
      throw new UnauthorizedException();
    }

    const session =
      await this.prisma.authSession.findUnique({
        where: { id: payload.sid },
        select: {
          userId: true,
          revokedAt: true,
          expiresAt: true,
          sessionVersion: true,
        },
      });

    if (
      !session ||
      session.userId !== payload.sub ||
      session.revokedAt ||
      session.expiresAt <= new Date() ||
      session.sessionVersion !== payload.sv
    ) {
      throw new UnauthorizedException(
        'Session revoked or expired.',
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        fullName: true,
        gender: true,
        role: true,
        isActive: true,
        sessionVersion: true,
        passwordHash: true,
        emailVerifiedAt: true,
        preferredLanguage: true,
        fontScale: true,
        highContrast: true,
        onboardingStep: true,
        onboardingCompletedAt: true,
      },
    });

    if (!user || !user.isActive || user.sessionVersion !== payload.sv) {
      throw new UnauthorizedException();
    }

    if (user.passwordHash && !user.emailVerifiedAt) {
      throw new UnauthorizedException('Email verification required.');
    }

    const {
      isActive: _isActive,
      sessionVersion: _sessionVersion,
      passwordHash: _passwordHash,
      emailVerifiedAt: _emailVerifiedAt,
      ...safeUser
    } = user;
    req.user = safeUser;
    req.sessionId = payload.sid;
    return true;
  }
}
