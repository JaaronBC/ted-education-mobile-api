import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  MaxLength,
  MinLength
} from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({ writeOnly: true })
  @IsString()
  @MinLength(1)
  currentPassword!: string;

  @ApiProperty({
    writeOnly: true,
    minLength: 12,
    maxLength: 72
  })
  @IsString()
  @MinLength(12)
  @MaxLength(72)
  newPassword!: string;
}
