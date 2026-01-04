import * as fc from 'fast-check';
import mongoose from 'mongoose';
import { ApprovalRequest } from '../ApprovalRequest';
import { User } from '../User';
import { DatabaseConnection } from '../../config/database';

/**
 * **Feature: auth-password-manager, Property 4: Request creation and duplicate prevention**
 * **Validates: Requirements 2.1, 2.3**
 */

describe('ApprovalRequest Model Property Tests', () => {
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
    // Clean up collections before each test
    await ApprovalRequest.deleteMany({});
    await User.deleteMany({});
  });

  describe('Property 4: Request creation and duplicate prevention', () => {
    it('should create approval requests and prevent duplicates for pending requests', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate test data for users and requests
          fc.array(
            fc.record({
              email: fc.string({ minLength: 3, maxLength: 20 })
                .filter(s => /^[a-zA-Z0-9]+$/.test(s))
                .map(s => `${s}@example.com`),
              password: fc.string({ minLength: 8, maxLength: 20 })
                .filter(s => /^[a-zA-Z0-9]+$/.test(s))
            }),
            { minLength: 1, maxLength: 5 }
          ),
          async (userData) => {
            // Create users first
            const users = [];
            for (const data of userData) {
              const user = await User.createUser({
                email: `${Date.now()}_${Math.random()}_${data.email}`, // Ensure uniqueness
                password: data.password
              });
              users.push(user);
            }

            // Property 4a: Should be able to create approval requests for each user
            const requests = [];
            for (const user of users) {
              const request = await ApprovalRequest.createRequest(user._id, user.email);
              requests.push(request);
              
              // Verify request was created correctly
              expect(request.userId.toString()).toBe(user._id.toString());
              expect(request.userEmail).toBe(user.email);
              expect(request.status).toBe('pending');
              expect(request.expiresAt).toBeInstanceOf(Date);
              expect(request.expiresAt.getTime()).toBeGreaterThan(Date.now());
            }

            // Property 4b: Should prevent duplicate pending requests for the same user
            for (const user of users) {
              await expect(
                ApprovalRequest.createRequest(user._id, user.email)
              ).rejects.toThrow('User already has a pending password request');
            }

            // Property 4c: Should allow new request after previous one is resolved
            const firstUser = users[0];
            const firstRequest = requests[0];
            
            // Approve the first request
            const adminId = new mongoose.Types.ObjectId();
            await firstRequest.approve(adminId, 'Test approval');
            
            // Should now be able to create a new request for the same user
            const newRequest = await ApprovalRequest.createRequest(firstUser._id, firstUser.email);
            expect(newRequest.status).toBe('pending');
            expect(newRequest._id.toString()).not.toBe(firstRequest._id.toString());

            // Property 4d: Should allow new request after previous one expires
            if (users.length > 1) {
              const secondUser = users[1];
              const secondRequest = requests[1];
              
              // Expire the second request
              await secondRequest.expire();
              
              // Should now be able to create a new request for the same user
              const newRequest2 = await ApprovalRequest.createRequest(secondUser._id, secondUser.email);
              expect(newRequest2.status).toBe('pending');
              expect(newRequest2._id.toString()).not.toBe(secondRequest._id.toString());
            }
          }
        ),
        { numRuns: 10 } // Reduced for performance
      );
    }, 30000); // 30 second timeout

    it('should handle request lifecycle state transitions correctly', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            email: fc.string({ minLength: 3, maxLength: 20 })
              .filter(s => /^[a-zA-Z0-9]+$/.test(s))
              .map(s => `${Date.now()}_${Math.random()}_${s}@example.com`),
            password: fc.string({ minLength: 8, maxLength: 20 })
              .filter(s => /^[a-zA-Z0-9]+$/.test(s)),
            reason: fc.string({ minLength: 1, maxLength: 100 })
              .filter(s => s.trim().length > 0)
          }),
          async ({ email, password, reason }) => {
            // Create user and request
            const user = await User.createUser({ email, password });
            const request = await ApprovalRequest.createRequest(user._id, user.email);
            const adminId = new mongoose.Types.ObjectId();

            // Property: Request should start as pending
            expect(request.status).toBe('pending');
            expect(request.canBeApproved()).toBe(true);

            // Property: Should be able to approve pending request
            await request.approve(adminId, reason);
            expect(request.status).toBe('approved');
            expect(request.adminResponse?.adminId.toString()).toBe(adminId.toString());
            expect(request.adminResponse?.reason).toBe(reason);
            expect(request.respondedAt).toBeInstanceOf(Date);
            expect(request.accessToken).toBeDefined();
            expect(request.isAccessTokenValid()).toBe(true);

            // Property: Cannot approve already approved request
            await expect(request.approve(adminId, 'Another reason')).rejects.toThrow();

            // Test denial path with a new request
            const request2 = await ApprovalRequest.createRequest(user._id, user.email);
            await request2.deny(adminId, reason);
            expect(request2.status).toBe('denied');
            expect(request2.adminResponse?.reason).toBe(reason);
            expect(request2.accessToken).toBeUndefined();

            // Property: Cannot deny already denied request
            await expect(request2.deny(adminId, 'Another reason')).rejects.toThrow();
          }
        ),
        { numRuns: 10 }
      );
    }, 30000);
  });
});