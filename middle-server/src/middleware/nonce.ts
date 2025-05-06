import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import winston from 'winston';

// Configure logger for security audit
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security-audit.log' })
  ]
});

interface NonceStore {
  [key: string]: {
    timestamp: number;
    used: boolean;
    ip?: string;
  };
}

const NONCE_TIMEOUT_SECONDS = 300; // 5 minutes
const MAX_NONCE_STORE_SIZE = 10000; // Prevent memory exhaustion
const nonceStore: NonceStore = {};

/**
 * Generate a cryptographically secure random nonce
 * @returns {string} A unique nonce
 */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Clean up expired and excess nonces
 */
function cleanupNonces(): void {
  const now = Date.now();
  const keysToRemove = Object.keys(nonceStore)
    .filter(key => 
      now - nonceStore[key].timestamp > NONCE_TIMEOUT_SECONDS * 1000
    );

  keysToRemove.forEach(key => delete nonceStore[key]);

  // Prevent potential memory exhaustion
  if (Object.keys(nonceStore).length > MAX_NONCE_STORE_SIZE) {
    const oldestKeys = Object.keys(nonceStore)
      .sort((a, b) => nonceStore[a].timestamp - nonceStore[b].timestamp)
      .slice(0, Object.keys(nonceStore).length - MAX_NONCE_STORE_SIZE);
    
    oldestKeys.forEach(key => delete nonceStore[key]);
  }
}

/**
 * Validate a nonce for request authentication
 * @param nonce The nonce to validate
 * @param ip Client IP address
 * @returns {boolean} Whether the nonce is valid
 */
export function validateNonce(nonce: string, ip?: string): boolean {
  // Perform cleanup
  cleanupNonces();

  // Check if nonce exists and hasn't been used
  if (!nonceStore[nonce]) {
    securityLogger.warn({
      message: 'Invalid nonce: Not found',
      nonce,
      ip
    });
    return false;
  }

  if (nonceStore[nonce].used) {
    securityLogger.warn({
      message: 'Invalid nonce: Already used',
      nonce,
      ip
    });
    return false;
  }

  // Optional: Add IP validation if provided
  if (ip && nonceStore[nonce].ip && nonceStore[nonce].ip !== ip) {
    securityLogger.warn({
      message: 'Invalid nonce: IP mismatch',
      nonce,
      expectedIp: nonceStore[nonce].ip,
      actualIp: ip
    });
    return false;
  }

  // Mark nonce as used
  nonceStore[nonce].used = true;

  securityLogger.info({
    message: 'Nonce validated successfully',
    nonce,
    ip
  });

  return true;
}

/**
 * Middleware to generate a nonce for authentication
 */
export const nonceGenerationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const nonce = generateNonce();
  const clientIp = req.ip;
  
  // Store nonce with timestamp and optional IP
  nonceStore[nonce] = {
    timestamp: Date.now(),
    used: false,
    ip: clientIp
  };

  securityLogger.info({
    message: 'Nonce generated',
    nonce,
    ip: clientIp
  });

  res.locals.nonce = nonce;
  next();
};

/**
 * Middleware to validate the nonce in the request
 */
export const nonceValidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const nonce = req.headers['x-nonce'] as string;
  const clientIp = req.ip;

  if (!nonce) {
    securityLogger.error({
      message: 'Nonce validation failed: Missing nonce',
      ip: clientIp
    });
    return res.status(400).json({ 
      error: 'Nonce is required',
      code: 'NONCE_MISSING' 
    });
  }

  if (!validateNonce(nonce, clientIp)) {
    return res.status(401).json({ 
      error: 'Invalid or expired nonce',
      code: 'NONCE_INVALID' 
    });
  }

  next();
};