import { createRequire } from 'node:module';

/**
 * Express 4 does not forward rejected promises from async handlers to the error
 * middleware, so a thrown DB error leaves the request hanging. This patches the
 * router Layer (same approach as express-async-errors) so every async handler's
 * rejection is passed to next(err). Import this module before creating routers.
 */
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const Layer = require('express/lib/router/layer');

const originalHandle = Layer.prototype.handle_request;
if (!originalHandle.__segmentraPatched) {
  const patched = function handle_request(this: any, req: any, res: any, next: (err?: unknown) => void) {
    const fn = this.handle;
    // Error-handling middleware (4 args) is invoked via handle_error, not here.
    if (fn.length > 3) return next();
    try {
      const ret = fn(req, res, next);
      if (ret && typeof ret.then === 'function' && typeof ret.catch === 'function') {
        ret.catch((err: unknown) => next(err ?? new Error('async_handler_rejected')));
      }
    } catch (err) {
      next(err);
    }
  };
  (patched as any).__segmentraPatched = true;
  Layer.prototype.handle_request = patched;
}
