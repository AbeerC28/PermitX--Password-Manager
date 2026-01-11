import { AuditLog } from '../models/AuditLog';
import { config } from '../config/environment';
import * as cron from 'node-cron';

export interface AuditRetentionPolicy {
  retentionDays: number;
  enabled: boolean;
  cronSchedule: string; // Cron expression for automatic cleanup
  lastCleanup?: Date;
  nextCleanup?: Date;
}

export interface AuditIntegrityCheck {
  checkId: string;
  timestamp: Date;
  totalChecked: number;
  issuesFound: number;
  integrityScore: number;
  issues: Array<{
    logId: string;
    issue: string;
    severity: 'low' | 'medium' | 'high';
    details: any;
  }>;
}

export class AuditService {
  private retentionPolicy: AuditRetentionPolicy;
  private cleanupJob?: cron.ScheduledTask;

  constructor() {
    // Initialize retention policy from config
    this.retentionPolicy = {
      retentionDays: config.auditRetentionDays || 90,
      enabled: config.auditRetentionEnabled !== false,
      cronSchedule: config.auditCleanupSchedule || '0 2 * * 0', // Weekly at 2 AM on Sunday
      lastCleanup: undefined,
      nextCleanup: undefined
    };

    this.initializeRetentionPolicy();
  }

  /**
   * Initialize automatic audit log retention policy
   */
  private initializeRetentionPolicy(): void {
    if (!this.retentionPolicy.enabled) {
      console.log('Audit log retention policy is disabled');
      return;
    }

    try {
      // Schedule automatic cleanup
      this.cleanupJob = cron.schedule(
        this.retentionPolicy.cronSchedule,
        async () => {
          console.log('Running scheduled audit log cleanup...');
          await this.performScheduledCleanup();
        },
        {
          timezone: 'UTC'
        }
      );

      // Calculate next cleanup time
      this.updateNextCleanupTime();

      console.log(`Audit log retention policy initialized:
        - Retention: ${this.retentionPolicy.retentionDays} days
        - Schedule: ${this.retentionPolicy.cronSchedule}
        - Next cleanup: ${this.retentionPolicy.nextCleanup?.toISOString()}`);

    } catch (error) {
      console.error('Failed to initialize audit retention policy:', error);
    }
  }

  /**
   * Update next cleanup time based on cron schedule
   */
  private updateNextCleanupTime(): void {
    try {
      // This is a simplified calculation - in production you might want to use a proper cron parser
      const now = new Date();
      const nextSunday = new Date(now);
      nextSunday.setDate(now.getDate() + (7 - now.getDay()) % 7);
      nextSunday.setHours(2, 0, 0, 0);
      
      if (nextSunday <= now) {
        nextSunday.setDate(nextSunday.getDate() + 7);
      }
      
      this.retentionPolicy.nextCleanup = nextSunday;
    } catch (error) {
      console.error('Failed to calculate next cleanup time:', error);
    }
  }

  /**
   * Perform scheduled cleanup
   */
  private async performScheduledCleanup(): Promise<void> {
    try {
      const deletedCount = await this.cleanupOldLogs();
      
      this.retentionPolicy.lastCleanup = new Date();
      this.updateNextCleanupTime();

      // Log the scheduled cleanup
      await AuditLog.create({
        action: 'scheduled_audit_cleanup',
        details: {
          deletedCount,
          retentionDays: this.retentionPolicy.retentionDays,
          scheduledCleanup: true,
          nextCleanup: this.retentionPolicy.nextCleanup?.toISOString()
        },
        ipAddress: 'system',
        userAgent: 'audit-service',
        timestamp: new Date(),
        severity: 'info'
      });

      console.log(`Scheduled audit cleanup completed: ${deletedCount} logs deleted`);

    } catch (error) {
      console.error('Scheduled audit cleanup failed:', error);
      
      // Log the cleanup failure
      await AuditLog.create({
        action: 'scheduled_audit_cleanup_error',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          retentionDays: this.retentionPolicy.retentionDays
        },
        ipAddress: 'system',
        userAgent: 'audit-service',
        timestamp: new Date(),
        severity: 'error'
      });
    }
  }

  /**
   * Manually cleanup old audit logs
   */
  async cleanupOldLogs(retentionDays?: number): Promise<number> {
    const days = retentionDays || this.retentionPolicy.retentionDays;
    return await AuditLog.cleanupOldLogs(days);
  }

  /**
   * Get current retention policy
   */
  getRetentionPolicy(): AuditRetentionPolicy {
    return { ...this.retentionPolicy };
  }

  /**
   * Update retention policy
   */
  async updateRetentionPolicy(policy: Partial<AuditRetentionPolicy>): Promise<void> {
    const oldPolicy = { ...this.retentionPolicy };

    // Update policy
    if (policy.retentionDays !== undefined) {
      this.retentionPolicy.retentionDays = Math.max(30, Math.min(365, policy.retentionDays));
    }
    
    if (policy.enabled !== undefined) {
      this.retentionPolicy.enabled = policy.enabled;
    }
    
    if (policy.cronSchedule !== undefined) {
      this.retentionPolicy.cronSchedule = policy.cronSchedule;
    }

    // Restart cleanup job if schedule changed
    if (policy.cronSchedule && policy.cronSchedule !== oldPolicy.cronSchedule) {
      if (this.cleanupJob) {
        this.cleanupJob.stop();
        this.cleanupJob.destroy();
      }
      this.initializeRetentionPolicy();
    }

    // Enable/disable job
    if (policy.enabled !== undefined) {
      if (policy.enabled && !oldPolicy.enabled) {
        this.initializeRetentionPolicy();
      } else if (!policy.enabled && oldPolicy.enabled) {
        if (this.cleanupJob) {
          this.cleanupJob.stop();
          this.cleanupJob.destroy();
          this.cleanupJob = undefined;
        }
      }
    }

    // Log policy change
    await AuditLog.create({
      action: 'audit_retention_policy_updated',
      details: {
        oldPolicy,
        newPolicy: this.retentionPolicy,
        changes: policy
      },
      ipAddress: 'system',
      userAgent: 'audit-service',
      timestamp: new Date(),
      severity: 'info'
    });
  }

  /**
   * Perform comprehensive audit log integrity check
   */
  async performIntegrityCheck(options: {
    startDate?: Date;
    endDate?: Date;
    sampleSize?: number;
    checkDuplicates?: boolean;
    checkTimestamps?: boolean;
    checkRequiredFields?: boolean;
    checkDataConsistency?: boolean;
  } = {}): Promise<AuditIntegrityCheck> {
    const {
      startDate,
      endDate,
      sampleSize = 1000,
      checkDuplicates = true,
      checkTimestamps = true,
      checkRequiredFields = true,
      checkDataConsistency = true
    } = options;

    const checkId = `integrity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const timestamp = new Date();

    // Build query
    const query: any = {};
    if (startDate) query.timestamp = { $gte: startDate };
    if (endDate) {
      if (!query.timestamp) query.timestamp = {};
      query.timestamp.$lte = endDate;
    }

    // Get sample of audit logs
    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .limit(sampleSize)
      .lean();

    const issues: AuditIntegrityCheck['issues'] = [];
    const requiredFields = ['action', 'ipAddress', 'userAgent', 'timestamp'];

    // Check required fields
    if (checkRequiredFields) {
      for (const log of logs) {
        for (const field of requiredFields) {
          if (!(log as any)[field]) {
            issues.push({
              logId: log._id.toString(),
              issue: `Missing required field: ${field}`,
              severity: 'high',
              details: { field, logAction: log.action }
            });
          }
        }
      }
    }

    // Check timestamps
    if (checkTimestamps) {
      const now = new Date();
      for (const log of logs) {
        if (log.timestamp > now) {
          issues.push({
            logId: log._id.toString(),
            issue: 'Future timestamp detected',
            severity: 'high',
            details: { timestamp: log.timestamp, logAction: log.action }
          });
        }

        // Check for timestamps that are too old (beyond reasonable system age)
        const twoYearsAgo = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000);
        if (log.timestamp < twoYearsAgo) {
          issues.push({
            logId: log._id.toString(),
            issue: 'Extremely old timestamp detected',
            severity: 'low',
            details: { timestamp: log.timestamp, logAction: log.action }
          });
        }
      }
    }

    // Check for duplicates
    if (checkDuplicates) {
      const logMap = new Map<string, any[]>();
      
      for (const log of logs) {
        const key = `${log.action}_${log.ipAddress}_${Math.floor(new Date(log.timestamp).getTime() / 1000)}`;
        if (!logMap.has(key)) {
          logMap.set(key, []);
        }
        logMap.get(key)!.push(log);
      }

      for (const [key, duplicateLogs] of logMap.entries()) {
        if (duplicateLogs.length > 1) {
          for (const log of duplicateLogs) {
            issues.push({
              logId: log._id.toString(),
              issue: 'Potential duplicate log entry',
              severity: 'medium',
              details: { 
                duplicateCount: duplicateLogs.length,
                logAction: log.action,
                timestamp: log.timestamp,
                duplicateKey: key
              }
            });
          }
        }
      }
    }

    // Check data consistency
    if (checkDataConsistency) {
      for (const log of logs) {
        // Check severity values
        if (log.severity && !['info', 'warning', 'error'].includes(log.severity)) {
          issues.push({
            logId: log._id.toString(),
            issue: 'Invalid severity level',
            severity: 'medium',
            details: { severity: log.severity, logAction: log.action }
          });
        }

        // Check for suspicious action patterns
        if (log.action && log.action.length > 100) {
          issues.push({
            logId: log._id.toString(),
            issue: 'Unusually long action name',
            severity: 'low',
            details: { actionLength: log.action.length, logAction: log.action }
          });
        }

        // Check IP address format
        if (log.ipAddress && log.ipAddress !== 'unknown' && log.ipAddress !== 'system') {
          const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
          const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
          
          if (!ipv4Regex.test(log.ipAddress) && !ipv6Regex.test(log.ipAddress) && 
              log.ipAddress !== 'localhost' && log.ipAddress !== '127.0.0.1') {
            issues.push({
              logId: log._id.toString(),
              issue: 'Invalid IP address format',
              severity: 'low',
              details: { ipAddress: log.ipAddress, logAction: log.action }
            });
          }
        }
      }
    }

    // Calculate integrity score
    const integrityScore = Math.max(0, 100 - (issues.length / logs.length * 100));

    const integrityCheck: AuditIntegrityCheck = {
      checkId,
      timestamp,
      totalChecked: logs.length,
      issuesFound: issues.length,
      integrityScore: Math.round(integrityScore * 100) / 100,
      issues
    };

    // Log the integrity check
    await AuditLog.create({
      action: 'audit_integrity_check_performed',
      details: {
        checkId,
        totalChecked: logs.length,
        issuesFound: issues.length,
        integrityScore: integrityCheck.integrityScore,
        checkOptions: options,
        dateRange: {
          startDate: startDate?.toISOString(),
          endDate: endDate?.toISOString()
        }
      },
      ipAddress: 'system',
      userAgent: 'audit-service',
      timestamp: new Date(),
      severity: issues.length > 0 ? 'warning' : 'info'
    });

    return integrityCheck;
  }

  /**
   * Get audit log statistics for a date range
   */
  async getAuditStatistics(startDate?: Date, endDate?: Date): Promise<{
    totalLogs: number;
    logsByAction: Record<string, number>;
    logsBySeverity: Record<string, number>;
    logsByHour: Record<string, number>;
    topIPs: Array<{ ip: string; count: number }>;
    topUserAgents: Array<{ userAgent: string; count: number }>;
    averageLogsPerDay: number;
    dateRange: { startDate?: string; endDate?: string };
  }> {
    const query: any = {};
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = startDate;
      if (endDate) query.timestamp.$lte = endDate;
    }

    // Get basic stats using existing method
    const basicStats = await AuditLog.getLogStats(startDate, endDate);

    // Get additional statistics
    const pipeline: any[] = [
      ...(Object.keys(query).length > 0 ? [{ $match: query }] : []),
      {
        $facet: {
          hourlyStats: [
            {
              $group: {
                _id: { $hour: '$timestamp' },
                count: { $sum: 1 }
              }
            }
          ],
          ipStats: [
            {
              $group: {
                _id: '$ipAddress',
                count: { $sum: 1 }
              }
            },
            { $sort: { count: -1 } },
            { $limit: 10 }
          ],
          userAgentStats: [
            {
              $group: {
                _id: '$userAgent',
                count: { $sum: 1 }
              }
            },
            { $sort: { count: -1 } },
            { $limit: 10 }
          ]
        }
      }
    ];

    const [aggregateResult] = await AuditLog.aggregate(pipeline);

    // Process hourly stats
    const logsByHour: Record<string, number> = {};
    for (let i = 0; i < 24; i++) {
      logsByHour[i.toString().padStart(2, '0')] = 0;
    }
    aggregateResult.hourlyStats.forEach((stat: any) => {
      logsByHour[stat._id.toString().padStart(2, '0')] = stat.count;
    });

    // Process IP stats
    const topIPs = aggregateResult.ipStats.map((stat: any) => ({
      ip: stat._id,
      count: stat.count
    }));

    // Process user agent stats
    const topUserAgents = aggregateResult.userAgentStats.map((stat: any) => ({
      userAgent: stat._id,
      count: stat.count
    }));

    // Calculate average logs per day
    const daysDiff = startDate && endDate 
      ? Math.max(1, Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24)))
      : 1;
    const averageLogsPerDay = Math.round(basicStats.totalLogs / daysDiff);

    return {
      totalLogs: basicStats.totalLogs,
      logsByAction: basicStats.logsByAction,
      logsBySeverity: basicStats.logsBySeverity,
      logsByHour,
      topIPs,
      topUserAgents,
      averageLogsPerDay,
      dateRange: {
        startDate: startDate?.toISOString(),
        endDate: endDate?.toISOString()
      }
    };
  }

  /**
   * Stop the audit service and cleanup resources
   */
  stop(): void {
    if (this.cleanupJob) {
      this.cleanupJob.stop();
      this.cleanupJob.destroy();
      this.cleanupJob = undefined;
    }
  }
}

// Export singleton instance
export const auditService = new AuditService();