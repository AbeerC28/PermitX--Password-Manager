import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { RedisConnection } from '../config/redis';
import { config } from '../config/environment';
import { AuditLog } from '../models/AuditLog';
import { notificationService } from './notificationService';

export interface SecurityEvent {
  type: 'failed_login' | 'rate_limit_exceeded' | 'suspicious_activity' | 'account_lockout';
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  timestamp: Date;
}

export interface AccountLockoutInfo {
  isLocked: boolean;
  lockoutUntil?: Date;
  failedAttempts: number;
  lastFailedAttempt?: Date;
}

export class SecurityService {
  private redis = RedisConnection.getInstance();
  private readonly maxFailedAttempts = 5;
  private readonly lockoutDurationMs = 30 * 60 * 1000; // 30 minutes
  private readonly suspiciousActivityThreshold = 10;
  private readonly rateLimitWindowMs = config.rateLimitWindowMs;
  private readonly rateLimitMaxRequests = config.rateLimitMaxRequests;

  constructor() {
    this.initializeRedis();
  }

  private async initializeRedis(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (error) {
      console.error('Failed to initialize Redis connection for SecurityService:', error);
      throw error;
    }
  }

  /**
   * Create rate limiting middleware for different endpoints
   */
  createRateLimiter(options?: {
    windowMs?: number;
    max?: number;
    message?: string;
    skipSuccessfulRequests?: boolean;
  }) {
    const windowMs = options?.windowMs || this.rateLimitWindowMs;
    const max = options?.max || this.rateLimitMaxRequests;
    const message = options?.message || 'Too many requests, please try again later';

    return rateLimit({
      windowMs,
      max,
      message: {
        error: message,
        retryAfter: Math.ceil(windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: options?.skipSuccessfulRequests || false,
      handler: async (req: Request, res: Response) => {
        // Log rate limit exceeded
        await this.logSecurityEvent({
          type: 'rate_limit_exceeded',
          ipAddress: this.getClientIP(req),
          userAgent: req.get('User-Agent') || 'Unknown',
          details: {
            endpoint: req.path,
            method: req.method,
            rateLimitWindow: windowMs,
            rateLimitMax: max
          },
          timestamp: new Date()
        });

        res.status(429).json({
          error: message,
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }
    });
  }

  /**
   * Strict rate limiter for authentication endpoints
   */
  createAuthRateLimiter() {
    return this.createRateLimiter({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 attempts per window
      message: 'Too many authentication attempts, please try again later',
      skipSuccessfulRequests: true
    });
  }

  /**
   * Moderate rate limiter for API endpoints
   */
  createAPIRateLimiter() {
    return this.createRateLimiter({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // 100 requests per window
      message: 'API rate limit exceeded, please try again later'
    });
  }

  /**
   * Strict rate limiter for password request endpoints
   */
  createPasswordRequestRateLimiter() {
    return this.createRateLimiter({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 3, // 3 password requests per hour
      message: 'Too many password requests, please try again later'
    });
  }

  /**
   * Record failed login attempt and check for account lockout
   */
  async recordFailedLogin(identifier: string, ipAddress: string, userAgent: string): Promise<AccountLockoutInfo> {
    try {
      const key = `failed_login:${identifier}`;
      const lockoutKey = `lockout:${identifier}`;
      
      // Check if account is currently locked
      const lockoutData = await this.redis.getClient().get(lockoutKey);
      if (lockoutData) {
        const lockoutInfo = JSON.parse(lockoutData);
        if (new Date(lockoutInfo.lockoutUntil) > new Date()) {
          return {
            isLocked: true,
            lockoutUntil: new Date(lockoutInfo.lockoutUntil),
            failedAttempts: lockoutInfo.failedAttempts,
            lastFailedAttempt: new Date(lockoutInfo.lastFailedAttempt)
          };
        } else {
          // Lockout expired, clean up
          await this.redis.getClient().del(lockoutKey);
          await this.redis.getClient().del(key);
        }
      }

      // Increment failed attempts
      const failedAttempts = await this.redis.getClient().incr(key);
      await this.redis.getClient().expire(key, 3600); // Expire in 1 hour

      const now = new Date();

      // Log failed login attempt
      await this.logSecurityEvent({
        type: 'failed_login',
        ipAddress,
        userAgent,
        details: {
          identifier,
          failedAttempts,
          threshold: this.maxFailedAttempts
        },
        timestamp: now
      });

      // Check if lockout threshold reached
      if (failedAttempts >= this.maxFailedAttempts) {
        const lockoutUntil = new Date(Date.now() + this.lockoutDurationMs);
        
        // Set lockout
        await this.redis.getClient().setEx(
          lockoutKey,
          Math.floor(this.lockoutDurationMs / 1000),
          JSON.stringify({
            lockoutUntil: lockoutUntil.toISOString(),
            failedAttempts,
            lastFailedAttempt: now.toISOString()
          })
        );

        // Log account lockout
        await this.logSecurityEvent({
          type: 'account_lockout',
          ipAddress,
          userAgent,
          details: {
            identifier,
            lockoutDuration: this.lockoutDurationMs,
            lockoutUntil: lockoutUntil.toISOString()
          },
          timestamp: now
        });

        return {
          isLocked: true,
          lockoutUntil,
          failedAttempts,
          lastFailedAttempt: now
        };
      }

      return {
        isLocked: false,
        failedAttempts,
        lastFailedAttempt: now
      };

    } catch (error) {
      console.error('Failed to record failed login:', error);
      return {
        isLocked: false,
        failedAttempts: 0
      };
    }
  }

  /**
   * Clear failed login attempts on successful login
   */
  async clearFailedLogins(identifier: string): Promise<void> {
    try {
      const key = `failed_login:${identifier}`;
      const lockoutKey = `lockout:${identifier}`;
      
      await this.redis.getClient().del(key);
      await this.redis.getClient().del(lockoutKey);
    } catch (error) {
      console.error('Failed to clear failed logins:', error);
    }
  }

  /**
   * Check if account is currently locked out
   */
  async isAccountLocked(identifier: string): Promise<AccountLockoutInfo> {
    try {
      const lockoutKey = `lockout:${identifier}`;
      const lockoutData = await this.redis.getClient().get(lockoutKey);
      
      if (!lockoutData) {
        return { isLocked: false, failedAttempts: 0 };
      }

      const lockoutInfo = JSON.parse(lockoutData);
      const lockoutUntil = new Date(lockoutInfo.lockoutUntil);
      
      if (lockoutUntil > new Date()) {
        return {
          isLocked: true,
          lockoutUntil,
          failedAttempts: lockoutInfo.failedAttempts,
          lastFailedAttempt: new Date(lockoutInfo.lastFailedAttempt)
        };
      } else {
        // Lockout expired, clean up
        await this.redis.getClient().del(lockoutKey);
        return { isLocked: false, failedAttempts: 0 };
      }
    } catch (error) {
      console.error('Failed to check account lockout:', error);
      return { isLocked: false, failedAttempts: 0 };
    }
  }

  /**
   * Detect suspicious activity patterns
   */
  async detectSuspiciousActivity(ipAddress: string, userAgent: string): Promise<boolean> {
    try {
      const key = `suspicious:${ipAddress}`;
      const windowMs = 60 * 60 * 1000; // 1 hour window
      
      // Get current activity count
      const activityCount = await this.redis.getClient().incr(key);
      await this.redis.getClient().expire(key, Math.floor(windowMs / 1000));

      if (activityCount >= this.suspiciousActivityThreshold) {
        // Log suspicious activity
        await this.logSecurityEvent({
          type: 'suspicious_activity',
          ipAddress,
          userAgent,
          details: {
            activityCount,
            threshold: this.suspiciousActivityThreshold,
            timeWindow: windowMs
          },
          timestamp: new Date()
        });

        return true;
      }

      return false;
    } catch (error) {
      console.error('Failed to detect suspicious activity:', error);
      return false;
    }
  }

  /**
   * Middleware to check for suspicious activity
   */
  suspiciousActivityMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const ipAddress = this.getClientIP(req);
        const userAgent = req.get('User-Agent') || 'Unknown';
        
        const isSuspicious = await this.detectSuspiciousActivity(ipAddress, userAgent);
        
        if (isSuspicious) {
          res.status(429).json({
            error: 'Suspicious activity detected. Access temporarily restricted.',
            retryAfter: 3600 // 1 hour
          });
          return;
        }

        next();
      } catch (error) {
        console.error('Suspicious activity middleware error:', error);
        next(); // Continue on error to avoid blocking legitimate requests
      }
    };
  }

  /**
   * Middleware to check account lockout status
   */
  accountLockoutMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const identifier = req.body.username || req.body.email;
        
        if (!identifier) {
          next(); // No identifier to check
          return;
        }

        const lockoutInfo = await this.isAccountLocked(identifier);
        
        if (lockoutInfo.isLocked) {
          const remainingTime = lockoutInfo.lockoutUntil 
            ? Math.ceil((lockoutInfo.lockoutUntil.getTime() - Date.now()) / 1000)
            : 0;

          res.status(423).json({
            error: 'Account temporarily locked due to multiple failed attempts',
            lockedUntil: lockoutInfo.lockoutUntil,
            retryAfter: remainingTime
          });
          return;
        }

        next();
      } catch (error) {
        console.error('Account lockout middleware error:', error);
        next(); // Continue on error to avoid blocking legitimate requests
      }
    };
  }

  /**
   * Log security events to audit log
   */
  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      await AuditLog.create({
        action: `security_${event.type}`,
        details: event.details,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        timestamp: event.timestamp,
        severity: event.type === 'suspicious_activity' || event.type === 'account_lockout' ? 'warning' : 'info'
      });
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  /**
   * Get client IP address from request
   */
  private getClientIP(req: Request): string {
    return (
      req.ip ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      (req.connection as any)?.socket?.remoteAddress ||
      req.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
      req.get('X-Real-IP') ||
      'unknown'
    );
  }

  /**
   * Generate security report for admin dashboard
   */
  async generateSecurityReport(hours: number = 24): Promise<{
    failedLogins: number;
    rateLimitExceeded: number;
    suspiciousActivity: number;
    accountLockouts: number;
    topIPs: Array<{ ip: string; count: number }>;
  }> {
    try {
      const since = new Date(Date.now() - (hours * 60 * 60 * 1000));
      
      // Get security events from audit log
      const events = await AuditLog.find({
        action: { $regex: /^security_/ },
        timestamp: { $gte: since }
      }).lean();

      const report = {
        failedLogins: 0,
        rateLimitExceeded: 0,
        suspiciousActivity: 0,
        accountLockouts: 0,
        topIPs: [] as Array<{ ip: string; count: number }>
      };

      const ipCounts: Record<string, number> = {};

      for (const event of events) {
        // Count by event type
        if (event.action === 'security_failed_login') {
          report.failedLogins++;
        } else if (event.action === 'security_rate_limit_exceeded') {
          report.rateLimitExceeded++;
        } else if (event.action === 'security_suspicious_activity') {
          report.suspiciousActivity++;
        } else if (event.action === 'security_account_lockout') {
          report.accountLockouts++;
        }

        // Count by IP
        if (event.ipAddress && event.ipAddress !== 'unknown') {
          ipCounts[event.ipAddress] = (ipCounts[event.ipAddress] || 0) + 1;
        }
      }

      // Get top IPs
      report.topIPs = Object.entries(ipCounts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      return report;
    } catch (error) {
      console.error('Failed to generate security report:', error);
      return {
        failedLogins: 0,
        rateLimitExceeded: 0,
        suspiciousActivity: 0,
        accountLockouts: 0,
        topIPs: []
      };
    }
  }

  /**
   * Manually unlock an account (admin function)
   */
  async unlockAccount(identifier: string, adminId: string, ipAddress: string, userAgent: string): Promise<boolean> {
    try {
      const key = `failed_login:${identifier}`;
      const lockoutKey = `lockout:${identifier}`;
      
      await this.redis.getClient().del(key);
      await this.redis.getClient().del(lockoutKey);

      // Log manual unlock
      await AuditLog.create({
        action: 'admin_account_unlock',
        adminId,
        details: { unlockedAccount: identifier },
        ipAddress,
        userAgent,
        timestamp: new Date(),
        severity: 'info'
      });

      return true;
    } catch (error) {
      console.error('Failed to unlock account:', error);
      return false;
    }
  }
}

// Export singleton instance
export const securityService = new SecurityService();