import { generateNonce, validateNonce } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';
import { nonceGenerationMiddleware, nonceValidationMiddleware } from '../../src/middleware/nonce';

describe('Nonce Middleware', () => {
  describe('generateNonce', () => {
    it('should generate unique nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).not.toEqual(nonce2);
      expect(nonce1.length).toBeGreaterThan(0);
    });

    it('should generate hex string nonces', () => {
      const nonce = generateNonce();
      expect(/^[0-9a-f]+$/.test(nonce)).toBeTruthy();
    });
  });

  describe('validateNonce', () => {
    it('should allow a valid nonce', () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBeTruthy();
    });

    it('should not allow a nonce twice', () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBeTruthy();
      expect(validateNonce(nonce)).toBeFalsy();
    });

    it('should not allow an invalid nonce', () => {
      const invalidNonce = 'invalid_nonce';
      expect(validateNonce(invalidNonce)).toBeFalsy();
    });

    it('should validate nonce with IP matching', () => {
      const nonce = generateNonce();
      const ip = '192.168.1.1';
      expect(validateNonce(nonce, ip)).toBeTruthy();
      expect(validateNonce(nonce, ip)).toBeFalsy(); // Cannot reuse
      expect(validateNonce(nonce, '10.0.0.1')).toBeFalsy(); // Different IP
    });
  });

  describe('nonceGenerationMiddleware', () => {
    it('should add nonce to res.locals', () => {
      const req = {} as Request;
      const res = { 
        locals: {},
        ip: '192.168.1.1'
      } as Response;
      const next = jest.fn() as NextFunction;

      nonceGenerationMiddleware(req, res, next);

      expect(res.locals.nonce).toBeDefined();
      expect(typeof res.locals.nonce).toBe('string');
      expect(next).toHaveBeenCalled();
    });
  });

  describe('nonceValidationMiddleware', () => {
    it('should reject requests without nonce', () => {
      const req = { 
        headers: {},
        ip: '192.168.1.1'
      } as Request;
      const res = { 
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn() as NextFunction;

      nonceValidationMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce is required',
        code: 'NONCE_MISSING'
      }));
      expect(next).not.toHaveBeenCalled();
    });

    it('should validate request with valid nonce', () => {
      const req = { 
        headers: {},
        ip: '192.168.1.1'
      } as Request;
      const res = { 
        locals: {},
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as unknown as Response;
      const next = jest.fn() as NextFunction;

      // First generate a nonce
      nonceGenerationMiddleware(req, res, () => {
        // Use the generated nonce
        req.headers['x-nonce'] = res.locals.nonce;

        nonceValidationMiddleware(req, res, next);

        expect(next).toHaveBeenCalled();
      });
    });
  });
});