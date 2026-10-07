import { Controller, Get, Param, Query } from '@nestjs/common';

import { ResourcesService } from './resources.service';
import type { Resource } from './resources.types';
import { ResourcesQueryDto } from './dto/resources-query.dto';

@Controller('resources')
export class ResourcesController {
  constructor(private readonly resourcesService: ResourcesService) {}

  @Get()
  findAll(@Query() query: ResourcesQueryDto): Resource[] {
    return this.resourcesService.findAll({
      language: query.language,
      category: query.category,
      search: query.search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): Resource {
    return this.resourcesService.findOne(id);
  }
}
