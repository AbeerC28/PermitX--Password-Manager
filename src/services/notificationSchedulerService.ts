import { ApprovalRequest } from '../models/ApprovalRequest';
import { AuditLog } from '../models/AuditLog';
import { sendAdminNotification, sendUserNotification } from './notificationService';

export class NotificationSchedulerService {
  private summaryInterval: NodeJS.Timeout | null = null;
  private escalationInterval: NodeJS.Timeout | null = null;
  private expirationInterval: NodeJS.Timeout | null = null;
  private lastAdminActivity: Date = new Date();
  private isRunning = false;

  /**
   * Start the notification scheduler
   */
  start(): void {
    if (this.isRunning) {
      console.log('Notification scheduler is already running');
      return;
    }

    this.isRunning = true;
    console.log('Starting notification scheduler service');

    // Send summary notifications every 30 minutes
    this.summaryInterval = setInterval(async () => {
      await this.sendSummaryNotifications();
    }, 30 * 60 * 1000); // 30 minutes

    // Check for escalation every 15 minutes
    this.escalationInterval = setInterval(async () => {
      await this.checkForEscalation();
    }, 15 * 60 * 1000); // 15 minutes

    // Check for expired requests every 5 minutes
    this.expirationInterval = setInterval(async () => {
      await this.handleRequestExpiration();
    }, 5 * 60 * 1000); // 5 minutes

    // Update admin activity tracking
    this.updateAdminActivity();
  }

  /**
   * Stop the notification scheduler
   */
  stop(): void {
    if (!this.isRunning) {
      return;
    }

    console.log('Stopping notification scheduler service');
    this.isRunning = false;

    if (this.summaryInterval) {
      clearInterval(this.summaryInterval);
      this.summaryInterval = null;
    }

    if (this.escalationInterval) {
      clearInterval(this.escalationInterval);
      this.escalationInterval = null;
    }

    if (this.expirationInterval) {
      clearInterval(this.expirationInterval);
      this.expirationInterval = null;
    }
  }

  /**
   * Send immediate notification for new request
   */
  async sendImmediateNotification(requestId: string, userEmail: string): Promise<void> {
    try {
      // Send immediate notification to admin
      await sendAdminNotification('newRequest', {
        userEmail,
        requestId,
        timestamp: new Date()
      });

      // Log immediate notification
      await AuditLog.create({
        action: 'immediate_notification_sent',
        details: {
          requestId,
          userEmail,
          type: 'new_request'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'info'
      });

      console.log(`Immediate notification sent for request ${requestId}`);
    } catch (error) {
      console.error('Failed to send immediate notification:', error);
      
      await AuditLog.create({
        action: 'immediate_notification_failed',
        details: {
          requestId,
          userEmail,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'error'
      });
      
      throw error;
    }
  }

  /**
   * Update the last admin activity timestamp
   */
  updateAdminActivity(): void {
    this.lastAdminActivity = new Date();
  }
  /**
   * Send summary notifications for pending requests
   */
  private async sendSummaryNotifications(): Promise<void> {
    try {
      // Get count of pending requests
      const pendingCount = await ApprovalRequest.countDocuments({ status: 'pending' });

      if (pendingCount === 0) {
        return; // No pending requests, no need to send summary
      }

      // Send summary notification to admin
      await sendAdminNotification('pendingSummary', {
        pendingCount,
        timestamp: new Date()
      });

      // Log summary notification
      await AuditLog.create({
        action: 'summary_notification_sent',
        details: {
          pendingCount,
          type: 'scheduled_summary'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'info'
      });

      console.log(`Summary notification sent: ${pendingCount} pending requests`);

    } catch (error) {
      console.error('Failed to send summary notification:', error);
      
      await AuditLog.create({
        action: 'summary_notification_failed',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Check if admin has been offline for more than 2 hours and send escalation
   */
  private async checkForEscalation(): Promise<void> {
    try {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - (2 * 60 * 60 * 1000)); // 2 hours ago

      // Check if admin has been inactive for more than 2 hours
      if (this.lastAdminActivity > twoHoursAgo) {
        return; // Admin has been active recently
      }

      // Get count of pending requests
      const pendingCount = await ApprovalRequest.countDocuments({ status: 'pending' });

      if (pendingCount === 0) {
        return; // No pending requests, no need to escalate
      }

      // Check if we've already sent an escalation in the last hour to avoid spam
      const oneHourAgo = new Date(now.getTime() - (60 * 60 * 1000));
      const recentEscalation = await AuditLog.findOne({
        action: 'escalation_notification_sent',
        timestamp: { $gte: oneHourAgo }
      });

      if (recentEscalation) {
        return; // Already sent escalation recently
      }

      // Send escalation notification
      await sendAdminNotification('escalation', {
        pendingCount,
        timestamp: new Date()
      });

      console.log(`Escalation notification sent: ${pendingCount} pending requests, admin offline for ${Math.floor((now.getTime() - this.lastAdminActivity.getTime()) / (60 * 60 * 1000))} hours`);

      // Log escalation notification
      await AuditLog.create({
        action: 'escalation_notification_sent',
        details: {
          pendingCount,
          adminOfflineFor: Math.floor((now.getTime() - this.lastAdminActivity.getTime()) / (60 * 60 * 1000)), // hours
          type: 'admin_offline_escalation'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'warning'
      });

    } catch (error) {
      console.error('Failed to check for escalation:', error);
      
      await AuditLog.create({
        action: 'escalation_check_failed',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Handle request expiration and send notifications
   */
  private async handleRequestExpiration(): Promise<void> {
    try {
      // Expire old requests
      const expiredCount = await ApprovalRequest.expireOldRequests();

      if (expiredCount > 0) {
        console.log(`Expired ${expiredCount} old requests`);
        
        // Send expiration notifications
        await this.sendExpirationNotifications();

        // Log expiration processing
        await AuditLog.create({
          action: 'requests_expired',
          details: {
            expiredCount,
            type: 'scheduled_expiration'
          },
          ipAddress: 'system',
          userAgent: 'notification-scheduler',
          timestamp: new Date(),
          severity: 'info'
        });
      }

      // Clean up very old expired requests (older than 7 days)
      const cleanedCount = await ApprovalRequest.cleanupExpiredRequests();
      if (cleanedCount > 0) {
        console.log(`Cleaned up ${cleanedCount} old expired requests`);
      }

    } catch (error) {
      console.error('Failed to handle request expiration:', error);
      
      await AuditLog.create({
        action: 'expiration_handling_failed',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Send immediate notification for expired requests
   */
  private async sendExpirationNotifications(): Promise<void> {
    try {
      // Find requests that just expired (within the last 5 minutes)
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const expiredRequests = await ApprovalRequest.find({
        status: 'expired',
        expiresAt: { $gte: fiveMinutesAgo, $lte: new Date() }
      });

      for (const request of expiredRequests) {
        try {
          // Send expiration notification to user
          await sendUserNotification('requestExpired', request.userEmail, {
            requestId: request._id.toString(),
            timestamp: new Date()
          });

          // Log expiration notification
          await AuditLog.create({
            action: 'expiration_notification_sent',
            userId: request.userId,
            details: {
              requestId: request._id,
              userEmail: request.userEmail,
              expiredAt: request.expiresAt
            },
            ipAddress: 'system',
            userAgent: 'notification-scheduler',
            timestamp: new Date(),
            severity: 'info'
          });

          console.log(`Expiration notification sent to ${request.userEmail} for request ${request._id}`);

        } catch (error) {
          console.error(`Failed to send expiration notification for request ${request._id}:`, error);
        }
      }

    } catch (error) {
      console.error('Failed to send expiration notifications:', error);
      
      await AuditLog.create({
        action: 'expiration_notifications_failed',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: 'system',
        userAgent: 'notification-scheduler',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Get the current status of the scheduler
   */
  getStatus(): {
    isRunning: boolean;
    lastAdminActivity: Date;
    nextSummaryIn?: number;
    nextEscalationCheckIn?: number;
  } {
    return {
      isRunning: this.isRunning,
      lastAdminActivity: this.lastAdminActivity,
      nextSummaryIn: this.summaryInterval ? 30 * 60 * 1000 : undefined,
      nextEscalationCheckIn: this.escalationInterval ? 15 * 60 * 1000 : undefined
    };
  }
}

export const notificationScheduler = new NotificationSchedulerService();