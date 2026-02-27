import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api/v1');

  // set global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true
      }
    })
  )

  // enable CORS
  app.enableCors({
    origin: process.env.CORS_ORIGIN?.split(',') ?? 'http://localhost:3000',
    Credential: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  });


  // enable swagger
  const config = new DocumentBuilder()
    .setTitle('Nest Commerce API')
    .setDescription('API documentation for Nest Commerce application')
    .setVersion('1.0.0')
    .addTag('auth')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      name: 'JWT',
      description: 'Enter JWT token',
      in: 'header'
    },
      'JWT-auth',
    )
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      name: 'JWT',
      description: 'Enter JWT token',
      in: 'header'
    },
      'refresh-token',
    )
    .addServer(process.env.API_SERVER_URL ?? 'http://localhost:3000', 'Development Server')
    .build()
    ;


  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
    },

    customSiteTitle: 'Nest Commerce API',
    customCss: `
      .swagger-ui .topbar { background-color: #4a90e2; }
      .swagger-ui .info {margin: 50px 0;}
      .swagger-ui .info .title { font-size: 2.5em; color: #4a90e2; }
      .swagger-ui .info .description { font-size: 1.2em; color: #333; } 
    `

  });


  await app.listen(process.env.PORT ?? 3000);
}
bootstrap().catch((err) => {
  Logger.error('Error starting server', err);
  process.exit(1);
});
