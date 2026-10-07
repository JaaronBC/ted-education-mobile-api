import { Controller, Get, Param, Query } from '@nestjs/common';

import { EducationService } from './education.service';
import type { EducationArticle } from './education.types';
import { EducationQueryDto } from './dto/education-query.dto';

@Controller('education')
export class EducationController {
  constructor(private readonly educationService: EducationService) {}

  @Get()
  findAll(@Query() query: EducationQueryDto): EducationArticle[] {
    return this.educationService.findAll({
      language: query.language,
      category: query.category,
      search: query.search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): EducationArticle {
    return this.educationService.findOne(id);
  }
}
