import { ApprovalRequest } from '../models/ApprovalRequest';
import { AuditLog } from '../models/AuditLog';
import { getSocketService } from './socketService';
import { sendUserNotification } from './notificationService';

export class ExpirationService {
  private intervalId: NodeJS.Timeout | null = null;
  private readonly checkIntervalMs = 60000; // Check every minute

  /**
   * Start the expiration monitoring service
   */
  public start(): void {
    if (this.intervalId) {
      console.log('Expiration service is already running');
      return;
    }

    console.log('Starting request expiration monitoring service');
    
    // Run initial check
    this.checkExpiredRequests();

    // Set up periodic checks
    this.intervalId = setInterval(() => {
      this.checkExpiredRequests();
    }, this.checkIntervalMs);
  }

  /**
   * Stop the expiration monitoring service
   */
  public stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      console.log('Expiration service stopped');
    }
  }

  /**
   * Check for expired requests and handle them
   */
  private async checkExpiredRequests(): Promise<void> {
    try {
      // Find requests that are pending but past their expiration time
      const expiredRequests = await ApprovalRequest.find({
        status: 'pending',
        expiresAt: { $lt: new Date() }
      });

      if (expiredRequests.length === 0) {
        return;
      }

      console.log(`Found ${expiredRequests.length} expired requests to process`);

      // Process each expired request
      for (const request of expiredRequests) {
        await this.expireRequest(request);
      }

      // Log the batch expiration
      await AuditLog.create({
        action: 'batch_request_expiration',
        details: { 
          expiredCount: expiredRequests.length,
          requestIds: expiredRequests.map(r => r._id.toString())
        },
        ipAddress: 'system',
        userAgent: 'expiration-service',
        timestamp: new Date(),
        severity: 'info'
      });

    } catch (error) {
      console.error('Error checking expired requests:', error);
      
      // Log the error
      await AuditLog.create({
        action: 'expiration_check_error',
        details: { 
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'expiration-service',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Expire a specific request and send notifications
   */
  private async expireRequest(request: any): Promise<void> {
    try {
      // Update request status to expired
      await request.expire();

      // Log the expiration
      await AuditLog.create({
        action: 'password_request_expired',
        userId: request.userId,
        details: { 
          requestId: request._id,
          userEmail: request.userEmail,
          requestedAt: request.requestedAt,
          expiredAt: new Date()
        },
        ipAddress: 'system',
        userAgent: 'expiration-service',
        timestamp: new Date(),
        severity: 'info'
      });

      // Send real-time notification to user
      try {
        const socketService = getSocketService();
        socketService.notifyUser(request.userEmail, 'request-expired', {
          requestId: request._id,
          status: 'expired',
          expiredAt: new Date(),
          originalRequestedAt: request.requestedAt,
          canAccessPassword: false
        });

        // Notify admins about the expiration
        socketService.notifyAdmins('request-expired', {
          requestId: request._id,
          userEmail: request.userEmail,
          status: 'expired',
          expiredAt: new Date(),
          originalRequestedAt: request.requestedAt
        });
      } catch (socketError) {
        console.error('Failed to send real-time expiration notification:', socketError);
      }

      // Send email/SMS notification to user
      try {
        await sendUserNotification('requestExpired', request.userEmail, {
          requestId: request._id.toString(),
          expiredAt: new Date(),
          originalRequestedAt: request.requestedAt
        });
      } catch (notificationError) {
        console.error('Failed to send expiration notification:', notificationError);
      }

      console.log(`Expired request ${request._id} for user ${request.userEmail}`);

    } catch (error) {
      console.error(`Error expiring request ${request._id}:`, error);
      
      // Log the error
      await AuditLog.create({
        action: 'request_expiration_error',
        userId: request.userId,
        details: { 
          requestId: request._id,
          userEmail: request.userEmail,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'expiration-service',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Manually expire a specific request (for admin actions)
   */
  public async expireRequestById(requestId: string, adminId?: string): Promise<boolean> {
    try {
      const request = await ApprovalRequest.getRequestById(requestId);
      
      if (!request) {
        return false;
      }

      if (request.status !== 'pending') {
        return false;
      }

      await this.expireRequest(request);

      // Log manual expiration if done by admin
      if (adminId) {
        await AuditLog.create({
          action: 'manual_request_expiration',
          adminId,
          userId: request.userId,
          details: { 
            requestId: request._id,
            userEmail: request.userEmail,
            expiredBy: 'admin'
          },
          ipAddress: 'system',
          userAgent: 'admin-action',
          timestamp: new Date(),
          severity: 'info'
        });
      }

      return true;
    } catch (error) {
      console.error(`Error manually expiring request ${requestId}:`, error);
      return false;
    }
  }

  /**
   * Get statistics about request expirations
   */
  public async getExpirationStats(): Promise<{
    pendingRequests: number;
    expiringSoon: number; // Expiring within next hour
    expiredToday: number;
  }> {
    try {
      const now = new Date();
      const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);
      const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

      const [pendingRequests, expiringSoon, expiredToday] = await Promise.all([
        ApprovalRequest.countDocuments({ status: 'pending' }),
        ApprovalRequest.countDocuments({
          status: 'pending',
          expiresAt: { $lte: oneHourFromNow, $gt: now }
        }),
        ApprovalRequest.countDocuments({
          status: 'expired',
          respondedAt: { $gte: startOfDay }
        })
      ]);

      return {
        pendingRequests,
        expiringSoon,
        expiredToday
      };
    } catch (error) {
      console.error('Error getting expiration stats:', error);
      return {
        pendingRequests: 0,
        expiringSoon: 0,
        expiredToday: 0
      };
    }
  }

  /**
   * Clean up old expired requests (older than 7 days)
   */
  public async cleanupOldExpiredRequests(): Promise<number> {
    try {
      const deletedCount = await ApprovalRequest.cleanupExpiredRequests();
      
      if (deletedCount > 0) {
        console.log(`Cleaned up ${deletedCount} old expired requests`);
        
        await AuditLog.create({
          action: 'expired_requests_cleanup',
          details: { 
            deletedCount
          },
          ipAddress: 'system',
          userAgent: 'expiration-service',
          timestamp: new Date(),
          severity: 'info'
        });
      }

      return deletedCount;
    } catch (error) {
      console.error('Error cleaning up old expired requests:', error);
      return 0;
    }
  }

  /**
   * Check if service is running
   */
  public isRunning(): boolean {
    return this.intervalId !== null;
  }
}

// Export singleton instance
export const expirationService = new ExpirationService();