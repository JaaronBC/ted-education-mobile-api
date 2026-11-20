
import {
  BadRequestException, ConflictException, Injectable,
  Logger, NotFoundException, ServiceUnavailableException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  S3Client, PutObjectCommand,
  GetObjectCommand, DeleteObjectCommand
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'node:crypto';
import sharp from 'sharp';
import { PrismaService } from '../prisma/prisma.service';

type Upload = { buffer: Buffer; size: number; mimetype: string };

@Injectable()
export class AvatarService {
  private readonly logger = new Logger(AvatarService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService
  ) {}

  private storage() {
    const account = this.config.get<string>('R2_ACCOUNT_ID')?.trim();
    const bucket = this.config.get<string>('R2_BUCKET')?.trim();
    const accessKeyId = this.config.get<string>('R2_ACCESS_KEY_ID')?.trim();
    const secretAccessKey = this.config.get<string>('R2_SECRET_ACCESS_KEY')?.trim();

    if (!account || !bucket || !accessKeyId ||
        !secretAccessKey || !/^[a-f0-9]{32}$/i.test(account)) {
      throw new ServiceUnavailableException(
        'Avatar storage is not configured.'
      );
    }

    return {
      bucket,
      client: new S3Client({
        region: 'auto',
        endpoint: 'https://' + account + '.r2.cloudflarestorage.com',
        credentials: { accessKeyId, secretAccessKey }
      })
    };
  }

  private validKey(id: string, key: string | null): key is string {
    return Boolean(key && key.startsWith('avatars/' + id + '/'));
  }

  private async signed(id: string, key: string) {
    if (!this.validKey(id, key)) {
      throw new BadRequestException('Invalid avatar reference.');
    }

    const { client, bucket } = this.storage();

    return getSignedUrl(
      client,
      new GetObjectCommand({ Bucket: bucket, Key: key }),
      { expiresIn: 300 }
    );
  }

  async get(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: { avatarUrl: true }
    });

    if (!user) throw new NotFoundException('Account not found.');

    return {
      url: this.validKey(id, user.avatarUrl)
        ? await this.signed(id, user.avatarUrl)
        : null
    };
  }

  private async cleanup(key: string) {
    try {
      const { client, bucket } = this.storage();
      await client.send(new DeleteObjectCommand({
        Bucket: bucket,
        Key: key
      }));
    } catch {
      this.logger.warn('Avatar cleanup failed.');
    }
  }

  async upload(id: string, file?: Upload) {
    if (!file?.buffer?.length || file.size <= 0 ||
        file.size > 3 * 1024 * 1024) {
      throw new BadRequestException('Choose a photo under 3 MB.');
    }

    let jpeg: Buffer;

    try {
      const image = sharp(file.buffer, {
        limitInputPixels: 20000000,
        failOn: 'error'
      });

      const meta = await image.metadata();

      if (!meta.format ||
          !['jpeg', 'png', 'webp'].includes(meta.format)) {
        throw Error('Unsupported format');
      }

      jpeg = await image
        .rotate()
        .resize(256, 256, { fit: 'cover' })
        .jpeg({ quality: 82, mozjpeg: true })
        .toBuffer();
    } catch {
      throw new BadRequestException(
        'Use a valid JPEG, PNG or WebP photo.'
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id },
      select: { avatarUrl: true }
    });

    if (!user) throw new NotFoundException('Account not found.');

    const { client, bucket } = this.storage();
    const key = 'avatars/' + id + '/' + randomUUID() + '.jpg';

    await client.send(new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: jpeg,
      ContentType: 'image/jpeg',
      CacheControl: 'private, max-age=300'
    }));

    let updated;

    try {
      updated = await this.prisma.user.updateMany({
        where: { id, avatarUrl: user.avatarUrl },
        data: { avatarUrl: key }
      });
    } catch (e) {
      await this.cleanup(key);
      throw e;
    }

    if (updated.count !== 1) {
      await this.cleanup(key);
      throw new ConflictException('Avatar changed elsewhere. Retry.');
    }

    if (this.validKey(id, user.avatarUrl)) {
      await this.cleanup(user.avatarUrl);
    }

    return { url: await this.signed(id, key) };
  }

  async remove(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: { avatarUrl: true }
    });

    if (!user) throw new NotFoundException('Account not found.');
    if (!user.avatarUrl) return { url: null };

    const result = await this.prisma.user.updateMany({
      where: { id, avatarUrl: user.avatarUrl },
      data: { avatarUrl: null }
    });

    if (result.count !== 1) {
      throw new ConflictException('Avatar changed elsewhere. Retry.');
    }

    if (this.validKey(id, user.avatarUrl)) {
      await this.cleanup(user.avatarUrl);
    }

    return { url: null };
  }
}
