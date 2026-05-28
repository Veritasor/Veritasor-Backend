import { type Express } from 'express';

export interface RouteInfo {
  method: string;
  path: string;
}

export class RouteMapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouteMapError';
  }
}

/**
 * Extracts route paths and methods from an Express application instance.
 * @param app Express application
 * @returns Array of route information objects
 */
export function generateRouteMap(app: Express): RouteInfo[] {
  if (!app || !app._router || !app._router.stack) {
    throw new RouteMapError('Invalid Express app instance: missing router stack');
  }

  const routes: RouteInfo[] = [];

  function processMiddleware(middleware: any, prefix = '') {
    if (!middleware) return;

    if (middleware.name === 'router' && middleware.handle && middleware.handle.stack) {
      let routerPath = prefix;

      // Extract from layer.regexp if present
      if (middleware.regexp && middleware.regexp.source !== '^\\\\/?$') {
        const source = middleware.regexp.source;
        // Clean Express regex like ^\/api\/health\/?(?=\/|$)
        const cleaned = source
          .replace(/^\^\\/, '')
          .replace(/\\\/\?\(\?=\\\/\|\$\)\\\/i$/, '')
          .replace(/\\\/\?\(\?=\\\/\|\$\)\//i, '') // some variants
          .replace(/\\\//g, '/');
        
        // Sometimes Express regex extraction leaves a trailing `/?(?=/|$)` or similar
        // if not caught by the above. We do a general clean.
        const cleanPath = cleaned.replace(/\/\?\(\?\=\/\|\$\)\/?/i, '').replace(/\/\?\(\?\=\/\|\$\)/g, '');
        
        if (cleanPath && cleanPath !== '/') {
          routerPath = prefix + '/' + cleanPath;
        }
      }

      for (const layer of middleware.handle.stack) {
        processMiddleware(layer, routerPath);
      }
    } else if (middleware.route) {
      const path = prefix + middleware.route.path;
      for (const method in middleware.route.methods) {
        if (middleware.route.methods[method]) {
          routes.push({
            method: method.toUpperCase(),
            path: path.replace(/\/+/g, '/'),
          });
        }
      }
    }
  }

  for (const layer of app._router.stack) {
    processMiddleware(layer);
  }

  return routes;
}
