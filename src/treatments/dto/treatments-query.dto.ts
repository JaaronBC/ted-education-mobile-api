import { IsOptional, IsEnum, IsString, MaxLength } from 'class-validator';
import { SupportedLanguages } from '../../constants/supported-languages';

export class TreatmentsQueryDto {
  @IsOptional()
  @IsEnum(SupportedLanguages)
  language?: SupportedLanguages;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  category?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  search?: string;
}
