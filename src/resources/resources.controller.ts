import { Controller, Get, Param, Query } from '@nestjs/common';

import { ResourcesService } from './resources.service';
import type { Resource } from './resources.types';

@Controller('resources')
export class ResourcesController {
  constructor(private readonly resourcesService: ResourcesService) {}

  @Get()
  findAll(
    @Query('language') language?: string,
    @Query('category') category?: string,
    @Query('search') search?: string,
  ): Resource[] {
    return this.resourcesService.findAll({
      language,
      category,
      search,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string): Resource {
    return this.resourcesService.findOne(id);
  }
}