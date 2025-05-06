import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

interface NonceStore {
  [key: string]: {
    timestamp: number;
    used: boolean;
  };
}

const NONCE_TIMEOUT_SECONDS = 300; // 5 minutes
const nonceStore: NonceStore = {};

/**
 * Generate a cryptographically secure random nonce
 * @returns {string} A unique nonce
 */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate a nonce for request authentication
 * @param nonce The nonce to validate
 * @returns {boolean} Whether the nonce is valid
 */
export function validateNonce(nonce: string): boolean {
  // Clean up expired nonces
  const now = Date.now();
  Object.keys(nonceStore).forEach(key => {
    if (now - nonceStore[key].timestamp > NONCE_TIMEOUT_SECONDS * 1000) {
      delete nonceStore[key];
    }
  });

  // Check if nonce exists and hasn't been used
  if (!nonceStore[nonce]) {
    return false;
  }

  if (nonceStore[nonce].used) {
    return false;
  }

  // Mark nonce as used
  nonceStore[nonce].used = true;
  return true;
}

/**
 * Middleware to generate a nonce for authentication
 */
export const nonceGenerationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const nonce = generateNonce();
  
  // Store nonce with timestamp
  nonceStore[nonce] = {
    timestamp: Date.now(),
    used: false
  };

  res.locals.nonce = nonce;
  next();
};

/**
 * Middleware to validate the nonce in the request
 */
export const nonceValidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const nonce = req.headers['x-nonce'] as string;

  if (!nonce) {
    return res.status(400).json({ error: 'Nonce is required' });
  }

  if (!validateNonce(nonce)) {
    return res.status(401).json({ error: 'Invalid or expired nonce' });
  }

  next();
};