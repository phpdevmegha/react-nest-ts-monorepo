import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { JwtPayload } from '../interfaces/jwt-payload';
import type { RequestWithUser } from '../interfaces/request-with-user';

/**
 * Injects the authenticated JWT payload (or one of its fields) into a handler
 * parameter. Usage: `@CurrentUser('sub') userId: number`.
 */
export const CurrentUser = createParamDecorator(
  (field: keyof JwtPayload | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user as JwtPayload | undefined;

    return field && user ? user[field] : user;
  },
);
