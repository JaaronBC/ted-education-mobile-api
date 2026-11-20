
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { compare, hash } from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { MfaService } from './mfa.service';
import { UpdateAccountDto } from './dto/update-account.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly mfa: MfaService,
    private readonly config: ConfigService,
  ) {}

  async login(dto: LoginDto) {
    const email = dto.email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user || !user.isActive || !user.passwordHash ||
        !(await compare(dto.password, user.passwordHash))) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    if (!user.emailVerifiedAt) {
      throw new ForbiddenException('Email verification required.');
    }

    return this.mfa.loginResult(user);
  }
  async register(dto: RegisterDto) {
    const email = dto.email.trim().toLowerCase();
    const fullName = dto.fullName.trim().replace(/\s+/g, ' ');

    if (fullName.length < 2) {
      throw new BadRequestException('Full name is required.');
    }

    if (Buffer.byteLength(dto.password, 'utf8') > 72) {
      throw new BadRequestException('Password is too long.');
    }

    const existing = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (existing) {
      throw new ConflictException('Email already registered.');
    }

    const passwordHash = await hash(dto.password, 12);

    try {
      return await this.prisma.user.create({
        data: {
          email,
          fullName,
          passwordHash,
          gender: dto.gender ?? null,
          role: Role.PATIENT,
        },
        select: {
          id: true,
          fullName: true,
          email: true,
          gender: true,
          role: true,
          createdAt: true,
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email already registered.');
      }

      throw error;
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    if (
      newPassword.length < 12 ||
      Buffer.byteLength(newPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'New password must have at least 12 characters and at most 72 UTF-8 bytes.',
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        isActive: true,
        passwordHash: true,
      },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Sign in again.');
    }

    if (!user.passwordHash) {
      throw new BadRequestException(
        'This account has no password. Use the linked sign-in provider.',
      );
    }

    const valid = await compare(
      currentPassword,
      user.passwordHash,
    );

    if (!valid) {
      throw new UnauthorizedException(
        'Current password is incorrect.',
      );
    }

    const reused = await compare(
      newPassword,
      user.passwordHash,
    );

    if (reused) {
      throw new BadRequestException(
        'Choose a password different from the current one.',
      );
    }

    const passwordHash = await hash(newPassword, 12);

    // Update password and revoke sessions atomically.
    await this.prisma.$transaction(async (tx) => {
      const changed = await tx.user.updateMany({
        where: {
          id: user.id,
          passwordHash: user.passwordHash,
          isActive: true,
        },
        data: {
          passwordHash,
          sessionVersion: { increment: 1 },
        },
      });

      if (changed.count !== 1) {
        throw new ConflictException(
          'Account changed. Sign in again and retry.',
        );
      }

      await tx.authSession.updateMany({
        where: {
          userId: user.id,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    });

    // Email notification is best-effort.
    // Mail failure must not undo the password change.
    const apiKey = this.config
      .get<string>('RESEND_API_KEY')?.trim();

    const from = this.config
      .get<string>('RESET_EMAIL_FROM')?.trim();

    if (apiKey && from) {
      try {
        const response = await fetch(
          'https://api.resend.com/emails',
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer ' + apiKey,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              from,
              to: [user.email],
              subject: 'TED Education: Your password was changed',
              text:
                'Your TED Education password was changed. ' +
                'If this was not you, contact TED support immediately.',
            }),
            signal: AbortSignal.timeout(4000),
          },
        );

        if (!response.ok) {
          console.warn(
            'Password-change notification could not be delivered.'
          );
        }
      } catch {
        console.warn(
          'Password-change notification could not be delivered.'
        );
      }
    }

    return {
      message: 'Password changed. All sessions have been revoked.',
    };
  }

  async updateAccount(userId: string, dto: UpdateAccountDto) {
    const values: Prisma.UserUpdateInput = {};

    if (dto.fullName !== undefined) {
      const name = dto.fullName.trim().replace(/\s+/g,' ');
      if (name.length < 2) {
        throw new BadRequestException('Name must contain at least 2 characters.');
      }
      values.fullName = name;
    }

    if (dto.gender !== undefined) values.gender = dto.gender;
    if (dto.preferredLanguage !== undefined)
      values.preferredLanguage = dto.preferredLanguage;
    if (dto.fontScale !== undefined)
      values.fontScale = dto.fontScale;
    if (dto.highContrast !== undefined)
      values.highContrast = dto.highContrast;
    if (dto.onboardingStep !== undefined)
      values.onboardingStep = dto.onboardingStep;

    if (dto.completeOnboarding === true) {
      values.onboardingStep = 3;
      values.onboardingCompletedAt = new Date();
    }

    return this.prisma.user.update({
      where: { id: userId },
      data: values,
      select: {
        id: true, email: true, fullName: true, gender: true,
        role: true, preferredLanguage: true, fontScale: true,
        highContrast: true, onboardingStep: true,
        onboardingCompletedAt: true
      }
    });
  }
}
