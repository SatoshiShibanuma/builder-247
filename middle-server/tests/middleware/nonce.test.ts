import { generateNonce, validateNonce } from '../../src/middleware/nonce';

describe('Nonce Middleware', () => {
  describe('generateNonce', () => {
    it('should generate unique nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).not.toEqual(nonce2);
      expect(nonce1.length).toBeGreaterThan(0);
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
  });
});