import { Controller, Get, Param, Query } from '@nestjs/common';

import { TreatmentsService } from './treatments.service';
import type { Treatment } from './treatments.types';

@Controller('treatments')
export class TreatmentsController {
  constructor(private readonly treatmentsService: TreatmentsService) {}

  @Get()
  findAll(
    @Query('language') language?: string,
    @Query('category') category?: string,
    @Query('search') search?: string,
  ): Treatment[] {
    return this.treatmentsService.findAll({
      language,
      category,
      search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): Treatment {
    return this.treatmentsService.findOne(id);
  }
}