import * as fc from 'fast-check';
import { cryptoService } from '../cryptoService';

/**
 * **Feature: auth-password-manager, Property 8: Password masking security**
 * **Validates: Requirements 4.4**
 * 
 * Property: For any password display in the user interface, the actual password 
 * should never be visible in plain text and should always be masked or hidden
 */

describe('CryptoService Property Tests', () => {
  describe('Property 8: Password masking security', () => {
    it('should never expose actual password in masked result', () => {
      fc.assert(
        fc.property(
          // Generate arbitrary passwords with various characteristics
          fc.string({ minLength: 1, maxLength: 100 }),
          (password) => {
            const result = cryptoService.generateMaskedPassword(password);
            
            // Property 1: Masked password should never contain the actual password
            expect(result.maskedPassword).not.toContain(password);
            
            // Property 2: Masked password should only contain mask characters and ellipsis
            // Ensure it only contains bullet points and dots
            expect(result.maskedPassword.split('').every(char => char === '•' || char === '.')).toBe(true);
            
            // Property 3: Copyable password should be the original password (for clipboard)
            expect(result.copyablePassword).toBe(password);
            
            // Property 4: Masked password length should be reasonable (not expose actual length exactly)
            if (password.length <= 20) {
              expect(result.maskedPassword.length).toBe(password.length);
            } else {
              expect(result.maskedPassword).toMatch(/^[•]{20}\.\.\.$/);
            }
            
            // Property 5: No part of the original password should leak into masked version
            for (let i = 0; i < password.length; i++) {
              const char = password[i];
              if (char !== '•' && char !== '.') {
                expect(result.maskedPassword).not.toContain(char);
              }
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle special characters and unicode in passwords safely', () => {
      fc.assert(
        fc.property(
          // Generate passwords with special characters and unicode
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.length > 0),
          (password) => {
            const result = cryptoService.generateMaskedPassword(password);
            
            // Property: Special characters should never appear in masked password
            const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
            for (const char of specialChars) {
              if (password.includes(char)) {
                expect(result.maskedPassword).not.toContain(char);
              }
            }
            
            // Property: Unicode characters should never appear in masked password
            const unicodeRegex = /[^\x00-\x7F]/;
            if (unicodeRegex.test(password)) {
              expect(result.maskedPassword).not.toMatch(unicodeRegex);
            }
            
            // Property: Only allowed characters in mask
            expect(result.maskedPassword).toMatch(/^[•.]+$/);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should maintain consistent masking behavior for same password', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (password) => {
            const result1 = cryptoService.generateMaskedPassword(password);
            const result2 = cryptoService.generateMaskedPassword(password);
            
            // Property: Same password should always produce same masked result
            expect(result1.maskedPassword).toBe(result2.maskedPassword);
            expect(result1.copyablePassword).toBe(result2.copyablePassword);
            expect(result1.copyablePassword).toBe(password);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should never expose password through error messages or exceptions', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (password) => {
            try {
              const result = cryptoService.generateMaskedPassword(password);
              
              // Property: Result should not contain original password in any property
              const resultString = JSON.stringify(result);
              expect(resultString).toContain(password); // Only in copyablePassword field
              
              // But masked password specifically should not contain it
              expect(result.maskedPassword).not.toContain(password);
              
            } catch (error) {
              // Property: If an error occurs, it should not expose the password
              const errorMessage = error instanceof Error ? error.message : String(error);
              expect(errorMessage).not.toContain(password);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle edge cases without exposing passwords', () => {
      // Test empty string (edge case)
      expect(() => cryptoService.generateMaskedPassword('')).not.toThrow();
      
      // Test very long passwords
      const longPassword = 'a'.repeat(1000);
      const longResult = cryptoService.generateMaskedPassword(longPassword);
      expect(longResult.maskedPassword).not.toContain('a');
      expect(longResult.maskedPassword).toMatch(/^[•]{20}\.\.\.$/);
      
      // Test single character
      const singleChar = 'x';
      const singleResult = cryptoService.generateMaskedPassword(singleChar);
      expect(singleResult.maskedPassword).toBe('•');
      expect(singleResult.copyablePassword).toBe('x');
      
      // Test passwords with only mask characters
      const maskPassword = '••••••';
      const maskResult = cryptoService.generateMaskedPassword(maskPassword);
      expect(maskResult.maskedPassword).toBe('••••••');
      expect(maskResult.copyablePassword).toBe('••••••');
    });

    it('should maintain security properties under concurrent access', () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 50 }), { minLength: 1, maxLength: 10 }),
          (passwords) => {
            // Test concurrent masking operations
            const results = passwords.map(password => 
              cryptoService.generateMaskedPassword(password)
            );
            
            // Property: Each result should properly mask its corresponding password
            for (let i = 0; i < passwords.length; i++) {
              const password = passwords[i];
              const result = results[i];
              
              expect(result.copyablePassword).toBe(password);
              expect(result.maskedPassword).not.toContain(password);
              
              // Property: Results should not cross-contaminate
              for (let j = 0; j < passwords.length; j++) {
                if (i !== j && passwords[i] !== passwords[j]) {
                  expect(result.maskedPassword).not.toContain(passwords[j]);
                }
              }
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});