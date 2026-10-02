import { Controller, Get, Param, Query } from '@nestjs/common';

import { EducationService } from './education.service';
import type { EducationArticle } from './education.types';

@Controller('education')
export class EducationController {
  constructor(private readonly educationService: EducationService) {}

  @Get()
  findAll(
    @Query('language') language?: string,
    @Query('category') category?: string,
    @Query('search') search?: string,
  ): EducationArticle[] {
    return this.educationService.findAll({
      language,
      category,
      search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): EducationArticle {
    return this.educationService.findOne(id);
  }
}