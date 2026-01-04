import * as fc from 'fast-check';
import mongoose from 'mongoose';
import { User } from '../User';
import { DatabaseConnection } from '../../config/database';

/**
 * **Feature: auth-password-manager, Property 1: Password encryption consistency**
 * **Validates: Requirements 1.1, 6.1**
 */

describe('User Model Property Tests', () => {
  beforeAll(async () => {
    const db = DatabaseConnection.getInstance();
    await db.connect();
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    const db = DatabaseConnection.getInstance();
    await db.disconnect();
  });

  beforeEach(async () => {
    // Clean up users collection before each test
    await User.deleteMany({});
  });

  describe('Property 1: Password encryption consistency', () => {
    it('should encrypt passwords consistently and never store plain text', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate simple test data
          fc.integer({ min: 1, max: 10000 }),
          fc.string({ minLength: 8, maxLength: 20 }).filter(s => /^[a-zA-Z0-9]+$/.test(s)),
          async (id, password) => {
            const email = `user${id}${Date.now()}@example.com`;
            
            // Create user with plain text password
            const user = await User.createUser({ email, password });
            
            // Property 1a: Password should be encrypted (not stored as plain text)
            expect(user.encryptedPassword).not.toBe(password);
            expect(user.encryptedPassword).toMatch(/^\$argon2/); // Argon2 hash format
            
            // Property 1b: Encrypted password should be consistent for verification
            const isValid = await user.verifyPassword(password);
            expect(isValid).toBe(true);
            
            // Property 1c: Wrong password should not verify
            const wrongPassword = password + 'X';
            const isInvalid = await user.verifyPassword(wrongPassword);
            expect(isInvalid).toBe(false);
          }
        ),
        { numRuns: 10 } // Reduced significantly for performance
      );
    }, 30000); // 30 second timeout

    it('should handle password updates with proper encryption', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            email: fc.string({ minLength: 3, maxLength: 20 })
              .filter(s => /^[a-zA-Z0-9]+$/.test(s))
              .map(s => `${s}${Date.now()}${Math.random()}@example.com`), // Unique email
            originalPassword: fc.string({ minLength: 8, maxLength: 50 })
              .filter(pwd => pwd.trim().length >= 8 && /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+$/.test(pwd)),
            newPassword: fc.string({ minLength: 8, maxLength: 50 })
              .filter(pwd => pwd.trim().length >= 8 && /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+$/.test(pwd))
          }).filter(({ originalPassword, newPassword }) => 
            originalPassword !== newPassword // Ensure passwords are different
          ),
          async ({ email, originalPassword, newPassword }) => {
            // Create user with original password
            const user = await User.createUser({ email, password: originalPassword });
            const originalHash = user.encryptedPassword;
            const originalUpdateTime = user.lastPasswordUpdate;
            
            // Wait a small amount to ensure timestamp difference
            await new Promise(resolve => setTimeout(resolve, 10));
            
            // Update password
            await user.updatePassword(newPassword);
            
            // Property: Password update should change the hash
            expect(user.encryptedPassword).not.toBe(originalHash);
            expect(user.encryptedPassword).toMatch(/^\$argon2/);
            
            // Property: Old password should no longer work
            expect(await user.verifyPassword(originalPassword)).toBe(false);
            
            // Property: New password should work
            expect(await user.verifyPassword(newPassword)).toBe(true);
            
            // Property: lastPasswordUpdate should be updated
            expect(user.lastPasswordUpdate.getTime()).toBeGreaterThan(originalUpdateTime.getTime());
          }
        ),
        { numRuns: 10 } // Reduced for performance
      );
    }, 30000); // 30 second timeout
  });
});