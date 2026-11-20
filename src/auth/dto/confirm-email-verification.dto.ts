import { IsEmail, Matches, MaxLength } from 'class-validator';

export class ConfirmEmailVerificationDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @Matches(/^[0-9]{8}$/)
  code!: string;
}
