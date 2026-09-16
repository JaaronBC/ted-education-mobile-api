import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api/v1');

  // Allow the mobile/web frontend to call the API during development.
  app.enableCors();

  await app.listen(process.env.PORT ?? 3000, '0.0.0.0');
}

bootstrap();