import { Controller, Get, Param, Query } from '@nestjs/common';

import { TreatmentsService } from './treatments.service';
import type { Treatment } from './treatments.types';
import { TreatmentsQueryDto } from './dto/treatments-query.dto';

@Controller('treatments')
export class TreatmentsController {
  constructor(private readonly treatmentsService: TreatmentsService) {}

  @Get()
  findAll(@Query() query: TreatmentsQueryDto): Treatment[] {
    return this.treatmentsService.findAll({
      language: query.language,
      category: query.category,
      search: query.search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): Treatment {
    return this.treatmentsService.findOne(id);
  }
}
