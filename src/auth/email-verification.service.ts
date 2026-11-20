import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createHmac,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';

const GENERIC = {
  message: 'If verification is needed, a code will be sent.',
};

const INVALID = 'Invalid or expired verification code.';

const CODE_LIFETIME = 10 * 60 * 1000;
const RESEND_DELAY = 60 * 1000;
const DAILY_WINDOW = 24 * 60 * 60 * 1000;

@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  private digest(userId: string, code: string): string {
    const secret = this.config.getOrThrow<string>(
      'EMAIL_VERIFICATION_SECRET',
    );

    return createHmac('sha256', secret)
      .update(`ted:verify-email:${userId}:${code}`)
      .digest('hex');
  }

  async requestCode(emailInput: string) {
    const key = this.config.get<string>(
      'RESEND_API_KEY',
    )?.trim();

    const from = this.config.get<string>(
      'RESET_EMAIL_FROM',
    )?.trim();

    if (!key || !from) {
      throw new ServiceUnavailableException(
        'Email service is not configured.',
      );
    }

    const email = emailInput.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
      },
    });

    if (
      !user ||
      !user.isActive ||
      !user.passwordHash ||
      user.emailVerifiedAt
    ) {
      return GENERIC;
    }

    const now = new Date();

    const resendCutoff = new Date(
      now.getTime() - RESEND_DELAY,
    );

    const windowCutoff = new Date(
      now.getTime() - DAILY_WINDOW,
    );

    const code = randomInt(100000000)
      .toString()
      .padStart(8, '0');

    const codeHash = this.digest(user.id, code);

    const expires = new Date(
      now.getTime() + CODE_LIFETIME,
    );

    const reserved =
      await this.prisma.$queryRaw<
        Array<{ userId: string }>
      >`
      INSERT INTO "EmailVerificationCode"
        (
          "userId",
          "codeHash",
          "attempts",
          "sentAt",
          "expiresAt",
          "sentInWindow",
          "windowStartedAt"
        )
      VALUES (
        ${user.id}::uuid,
        ${codeHash},
        0,
        ${now},
        ${expires},
        1,
        ${now}
      )
      ON CONFLICT ("userId") DO UPDATE SET
        "codeHash" = EXCLUDED."codeHash",
        "attempts" = 0,
        "sentAt" = EXCLUDED."sentAt",
        "expiresAt" = EXCLUDED."expiresAt",
        "sentInWindow" = CASE
          WHEN "EmailVerificationCode"."windowStartedAt" > ${windowCutoff}
          THEN "EmailVerificationCode"."sentInWindow" + 1
          ELSE 1
        END,
        "windowStartedAt" = CASE
          WHEN "EmailVerificationCode"."windowStartedAt" > ${windowCutoff}
          THEN "EmailVerificationCode"."windowStartedAt"
          ELSE EXCLUDED."windowStartedAt"
        END
      WHERE
        "EmailVerificationCode"."sentAt" <= ${resendCutoff}
        AND (
          "EmailVerificationCode"."windowStartedAt" <= ${windowCutoff}
          OR "EmailVerificationCode"."sentInWindow" < 5
        )
      RETURNING "userId"
    `;

    if (reserved.length !== 1) {
      return GENERIC;
    }

    try {
      const response = await fetch(
        'https://api.resend.com/emails',
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + key,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from,
            to: [email],
            subject: 'TED Education: Verify your email',
            text:
              'Your verification code is ' + code +
              '. It expires in 10 minutes. ' +
              'If you did not register, ignore this email.',
          }),
          signal: AbortSignal.timeout(10000),
        },
      );

      if (!response.ok) {
        throw new Error(
          'Email HTTP ' + response.status,
        );
      }
    } catch (error) {
      this.logger.warn(
        error instanceof Error
          ? error.message
          : 'Email delivery failed',
      );

      // Do not reset the quota on a failed mail request.
      // Delivery may have succeeded despite a timeout.
    }

    return GENERIC;
  }

  async confirmCode(emailInput: string, code: string) {
    const email = emailInput.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
      },
    });

    if (
      !user ||
      !user.isActive ||
      !user.passwordHash ||
      user.emailVerifiedAt
    ) {
      throw new BadRequestException(INVALID);
    }

    const record =
      await this.prisma.emailVerificationCode.findUnique({
        where: { userId: user.id },
      });

    if (
      !record ||
      record.expiresAt <= new Date() ||
      record.attempts >= 5
    ) {
      throw new BadRequestException(INVALID);
    }

    const actual = Buffer.from(record.codeHash, 'hex');
    const expected = Buffer.from(
      this.digest(user.id, code),
      'hex',
    );

    if (
      actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)
    ) {
      await this.prisma.emailVerificationCode.updateMany({
        where: {
          userId: user.id,
          codeHash: record.codeHash,
          attempts: { lt: 5 },
        },
        data: {
          attempts: { increment: 1 },
        },
      });

      throw new BadRequestException(INVALID);
    }

    await this.prisma.$transaction(async (tx) => {
      const consumed =
        await tx.emailVerificationCode.deleteMany({
          where: {
            userId: user.id,
            codeHash: record.codeHash,
            attempts: { lt: 5 },
            expiresAt: { gt: new Date() },
          },
        });

      if (consumed.count !== 1) {
        throw new BadRequestException(INVALID);
      }

      const updated = await tx.user.updateMany({
        where: {
          id: user.id,
          emailVerifiedAt: null,
        },
        data: {
          emailVerifiedAt: new Date(),
        },
      });

      if (updated.count !== 1) {
        throw new BadRequestException(INVALID);
      }
    });

    return {
      message: 'Email verified. You can now sign in.',
    };
  }
}