import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { IsString, Matches } from 'class-validator';

import { AuthSessionService } from './auth-session.service';
import { JwtAuthGuard } from './jwt-auth.guard';

class RefreshDto {
  @IsString()
  @Matches(
    /^[0-9a-f]{8}-[0-9a-f-]{27,}\.[A-Za-z0-9_-]{43}$/i,
  )
  refreshToken!: string;
}

@Controller('auth')
export class AuthSessionController {
  constructor(
    private readonly sessions: AuthSessionService,
  ) {}

  @Post('refresh')
  @HttpCode(200)
  @Throttle({
    default: { limit: 10, ttl: 60000 },
  })
  refresh(@Body() dto: RefreshDto) {
    return this.sessions.refresh(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle({
    default: {
      limit: 10,
      ttl: 60000,
    },
  })
  logout(
    @Req()
    req: {
      user: { id: string };
      sessionId: string;
    },
  ) {
    return this.sessions.logoutCurrent(
      req.user.id,
      req.sessionId,
    );
  }

  @Post('logout-all')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  logoutAll(@Req() req: { user: { id: string } }) {
    return this.sessions.logoutAll(req.user.id);
  }
}
