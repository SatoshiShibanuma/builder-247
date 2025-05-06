import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// Configuration Constants
const NONCE_TIMEOUT_MS = 300000; // 5 minutes
const MAX_NONCE_STORE_SIZE = 10000; // Prevent memory exhaustion
const NONCE_LENGTH = 64; // Recommended nonce length

// Logging interface to allow flexible logging strategies
interface NonceLogger {
  log(level: 'info' | 'warn' | 'error', message: string, context?: Record<string, any>): void;
}

// Minimal default logger if no external logger is provided
class ConsoleNonceLogger implements NonceLogger {
  log(level: 'info' | 'warn' | 'error', message: string, context?: Record<string, any>): void {
    const formattedContext = context ? ` ${JSON.stringify(context)}` : '';
    console[level](`[Nonce ${level.toUpperCase()}] ${message}${formattedContext}`);
  }
}

interface NonceEntry {
  timestamp: number;
  used: boolean;
  ipAddress?: string;
}

class NonceMiddleware {
  private nonceStore: Map<string, NonceEntry>;
  private logger: NonceLogger;

  constructor(logger?: NonceLogger) {
    this.nonceStore = new Map();
    this.logger = logger || new ConsoleNonceLogger();
  }

  /**
   * Generate a cryptographically secure nonce
   */
  generateNonce(): string {
    return crypto.randomBytes(NONCE_LENGTH / 2).toString('hex');
  }

  /**
   * Clean up expired and excess nonces
   */
  private cleanupNonces(): void {
    const now = Date.now();
    const excessNonces = Array.from(this.nonceStore.entries())
      .filter(([_, entry]) => now - entry.timestamp > NONCE_TIMEOUT_MS);

    excessNonces.forEach(([nonce]) => this.nonceStore.delete(nonce));

    if (this.nonceStore.size > MAX_NONCE_STORE_SIZE) {
      const oldestNonces = Array.from(this.nonceStore.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp)
        .slice(0, this.nonceStore.size - MAX_NONCE_STORE_SIZE);

      oldestNonces.forEach(([nonce]) => this.nonceStore.delete(nonce));
    }
  }

  /**
   * Validate a nonce with optional IP verification
   */
  validateNonce(nonce: string, ipAddress?: string): boolean {
    this.cleanupNonces();

    const nonceEntry = this.nonceStore.get(nonce);

    if (!nonceEntry) {
      this.logger.log('warn', 'Invalid nonce: Not found', { nonce, ipAddress });
      return false;
    }

    if (nonceEntry.used) {
      this.logger.log('warn', 'Invalid nonce: Already used', { nonce, ipAddress });
      return false;
    }

    if (ipAddress && nonceEntry.ipAddress && nonceEntry.ipAddress !== ipAddress) {
      this.logger.log('warn', 'Invalid nonce: IP mismatch', { 
        nonce, 
        expectedIp: nonceEntry.ipAddress, 
        actualIp: ipAddress 
      });
      return false;
    }

    // Mark nonce as used
    nonceEntry.used = true;
    this.logger.log('info', 'Nonce validated successfully', { nonce, ipAddress });
    return true;
  }

  /**
   * Middleware to generate a nonce
   */
  nonceGenerationMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    const nonce = this.generateNonce();
    const ipAddress = req.ip;

    this.nonceStore.set(nonce, {
      timestamp: Date.now(),
      used: false,
      ipAddress
    });

    this.logger.log('info', 'Nonce generated', { nonce, ipAddress });
    res.locals.nonce = nonce;
    next();
  }

  /**
   * Middleware to validate nonce
   */
  nonceValidationMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    const nonce = req.headers['x-nonce'] as string;
    const ipAddress = req.ip;

    if (!nonce) {
      this.logger.log('error', 'Nonce validation failed: Missing nonce', { ipAddress });
      return res.status(400).json({ 
        error: 'Nonce is required',
        code: 'NONCE_MISSING'
      });
    }

    if (!this.validateNonce(nonce, ipAddress)) {
      return res.status(401).json({ 
        error: 'Invalid or expired nonce',
        code: 'NONCE_INVALID'
      });
    }

    next();
  }
}

// Export a singleton instance
export const nonceMiddleware = new NonceMiddleware();
export const { 
  nonceGenerationMiddleware, 
  nonceValidationMiddleware 
} = nonceMiddleware;