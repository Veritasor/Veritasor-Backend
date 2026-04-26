import { describe, it, expect } from 'vitest';
import express from 'express';
import { generateRouteMap, RouteMapError } from '../../src/utils/routeMap.js';

describe('Route Map Generator', () => {
  it('should throw an error for an invalid app instance', () => {
    expect(() => generateRouteMap({} as express.Express)).toThrow(RouteMapError);
    expect(() => generateRouteMap({} as express.Express)).toThrow(
      'Invalid Express app instance: missing router stack',
    );
  });

  it('should extract routes from a simple express app', () => {
    const app = express();
    app.get('/test', (req, res) => { res.send('ok'); });
    app.post('/api/data', (req, res) => { res.send('ok'); });

    const routes = generateRouteMap(app);

    expect(routes).toContainEqual({ method: 'GET', path: '/test' });
    expect(routes).toContainEqual({ method: 'POST', path: '/api/data' });
  });

  it('should handle nested routers', () => {
    const app = express();
    const router = express.Router();
    
    router.get('/users', (req, res) => { res.send('users'); });
    router.post('/users', (req, res) => { res.send('create user'); });
    
    const nestedRouter = express.Router();
    nestedRouter.delete('/:id', (req, res) => { res.send('delete'); });
    
    router.use('/nested', nestedRouter);
    app.use('/api', router);

    const routes = generateRouteMap(app);

    expect(routes).toContainEqual({ method: 'GET', path: '/api/users' });
    expect(routes).toContainEqual({ method: 'POST', path: '/api/users' });
    expect(routes).toContainEqual({ method: 'DELETE', path: '/api/nested/:id' });
  });

  it('should normalize paths with multiple slashes', () => {
    const app = express();
    app.get('///multiple//slashes/', (req, res) => { res.send('ok'); });
    
    const routes = generateRouteMap(app);
    
    expect(routes).toContainEqual({ method: 'GET', path: '/multiple/slashes/' });
  });
});
