import { nonceMiddleware } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';

describe('Nonce Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    mockReq = {
      headers: {},
      ip: '192.168.1.1'
    };
    mockRes = {
      locals: {},
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  describe('generateNonce', () => {
    it('should generate unique nonces', () => {
      const nonce1 = nonceMiddleware.generateNonce();
      const nonce2 = nonceMiddleware.generateNonce();
      
      expect(nonce1).not.toEqual(nonce2);
      expect(nonce1.length).toBe(64);
    });
  });

  describe('nonceGenerationMiddleware', () => {
    it('should generate and attach nonce to res.locals', () => {
      nonceMiddleware.nonceGenerationMiddleware(
        mockReq as Request, 
        mockRes as Response, 
        mockNext
      );

      expect(mockRes.locals.nonce).toBeDefined();
      expect(typeof mockRes.locals.nonce).toBe('string');
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('nonceValidationMiddleware', () => {
    it('should reject requests without nonce', () => {
      nonceMiddleware.nonceValidationMiddleware(
        mockReq as Request, 
        mockRes as Response, 
        mockNext
      );

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        code: 'NONCE_MISSING'
      }));
    });

    it('should validate request with correct nonce', () => {
      // First generate a nonce
      nonceMiddleware.nonceGenerationMiddleware(
        mockReq as Request, 
        mockRes as Response, 
        () => {
          // Use the generated nonce
          mockReq.headers['x-nonce'] = mockRes.locals.nonce;

          nonceMiddleware.nonceValidationMiddleware(
            mockReq as Request, 
            mockRes as Response, 
            mockNext
          );

          expect(mockNext).toHaveBeenCalled();
        }
      );
    });

    it('should reject reused nonce', () => {
      // First generate a nonce
      nonceMiddleware.nonceGenerationMiddleware(
        mockReq as Request, 
        mockRes as Response, 
        () => {
          // Use the generated nonce
          mockReq.headers['x-nonce'] = mockRes.locals.nonce;

          // First validation should pass
          nonceMiddleware.nonceValidationMiddleware(
            mockReq as Request, 
            mockRes as Response, 
            mockNext
          );

          // Reset mocks
          (mockRes.status as jest.Mock).mockClear();
          (mockRes.json as jest.Mock).mockClear();
          (mockNext as jest.Mock).mockClear();

          // Second validation should fail
          nonceMiddleware.nonceValidationMiddleware(
            mockReq as Request, 
            mockRes as Response, 
            mockNext
          );

          expect(mockRes.status).toHaveBeenCalledWith(401);
          expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
            code: 'NONCE_INVALID'
          }));
        }
      );
    });
  });
});