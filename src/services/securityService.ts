import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { RedisConnection } from '../config/redis';
import { config } from '../config/environment';
import { AuditLog } from '../models/AuditLog';
import { sendAdminNotification } from './notificationService';

export interface SecurityEvent {
  type: 'failed_login' | 'rate_limit_exceeded' | 'suspicious_activity' | 'account_lockout' | 'brute_force_attack' | 'unusual_access_pattern' | 'multiple_ip_access';
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityAlert {
  id: string;
  type: SecurityEvent['type'];
  severity: SecurityEvent['severity'];
  message: string;
  details: Record<string, any>;
  ipAddress: string;
  timestamp: Date;
  acknowledged: boolean;
}

export interface IPAnalysis {
  ipAddress: string;
  requestCount: number;
  failedLogins: number;
  suspiciousActivities: number;
  firstSeen: Date;
  lastSeen: Date;
  userAgents: string[];
  endpoints: string[];
  riskScore: number;
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
  private readonly alertThresholds = {
    bruteForce: 10, // Failed logins from same IP in 1 hour
    multipleIPs: 5, // Same user from different IPs in 1 hour
    unusualPattern: 20, // Requests from same IP in 10 minutes
    criticalEvents: 1 // Immediate alert for critical events
  };

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
          timestamp: new Date(),
          severity: 'medium'
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
        timestamp: now,
        severity: failedAttempts >= this.maxFailedAttempts ? 'high' : 'medium'
      });

      // Check for brute force attack
      await this.detectBruteForceAttack(ipAddress, userAgent);

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
          timestamp: now,
          severity: 'high'
        });

        // Generate critical security alert
        await this.generateSecurityAlert({
          type: 'account_lockout',
          severity: 'high',
          ipAddress,
          userAgent,
          details: {
            identifier,
            lockoutDuration: this.lockoutDurationMs,
            lockoutUntil: lockoutUntil.toISOString()
          }
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
          timestamp: new Date(),
          severity: 'medium'
        });

        // Generate security alert
        await this.generateSecurityAlert({
          type: 'suspicious_activity',
          severity: 'medium',
          ipAddress,
          userAgent,
          details: { activityCount, threshold: this.suspiciousActivityThreshold }
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
   * Analyze IP address for security risks
   */
  async analyzeIPAddress(ipAddress: string): Promise<IPAnalysis> {
    try {
      const key = `ip_analysis:${ipAddress}`;
      const windowMs = 24 * 60 * 60 * 1000; // 24 hours
      const since = new Date(Date.now() - windowMs);

      // Get events from audit log for this IP
      const events = await AuditLog.find({
        ipAddress,
        timestamp: { $gte: since }
      }).lean();

      const analysis: IPAnalysis = {
        ipAddress,
        requestCount: events.length,
        failedLogins: 0,
        suspiciousActivities: 0,
        firstSeen: events.length > 0 ? new Date(Math.min(...events.map(e => e.timestamp.getTime()))) : new Date(),
        lastSeen: events.length > 0 ? new Date(Math.max(...events.map(e => e.timestamp.getTime()))) : new Date(),
        userAgents: [...new Set(events.map(e => e.userAgent).filter(Boolean))],
        endpoints: [...new Set(events.map(e => e.details?.endpoint).filter(Boolean))],
        riskScore: 0
      };

      // Count specific event types
      for (const event of events) {
        if (event.action === 'security_failed_login') {
          analysis.failedLogins++;
        }
        if (event.action === 'security_suspicious_activity') {
          analysis.suspiciousActivities++;
        }
      }

      // Calculate risk score
      analysis.riskScore = this.calculateRiskScore(analysis);

      // Cache analysis for 1 hour
      await this.redis.getClient().setEx(
        key,
        3600,
        JSON.stringify(analysis)
      );

      return analysis;
    } catch (error) {
      console.error('Failed to analyze IP address:', error);
      return {
        ipAddress,
        requestCount: 0,
        failedLogins: 0,
        suspiciousActivities: 0,
        firstSeen: new Date(),
        lastSeen: new Date(),
        userAgents: [],
        endpoints: [],
        riskScore: 0
      };
    }
  }

  /**
   * Calculate risk score for an IP address
   */
  private calculateRiskScore(analysis: IPAnalysis): number {
    let score = 0;

    // High request volume
    if (analysis.requestCount > 100) score += 20;
    else if (analysis.requestCount > 50) score += 10;

    // Failed login attempts
    if (analysis.failedLogins > 10) score += 30;
    else if (analysis.failedLogins > 5) score += 15;

    // Suspicious activities
    score += analysis.suspiciousActivities * 10;

    // Multiple user agents (potential bot)
    if (analysis.userAgents.length > 5) score += 15;

    // Multiple endpoints accessed
    if (analysis.endpoints.length > 10) score += 10;

    // Time-based patterns (very recent activity)
    const hoursSinceFirst = (Date.now() - analysis.firstSeen.getTime()) / (1000 * 60 * 60);
    if (hoursSinceFirst < 1 && analysis.requestCount > 20) score += 25;

    return Math.min(score, 100); // Cap at 100
  }

  /**
   * Detect brute force attacks
   */
  async detectBruteForceAttack(ipAddress: string, userAgent: string): Promise<boolean> {
    try {
      const key = `brute_force:${ipAddress}`;
      const windowMs = 60 * 60 * 1000; // 1 hour window
      
      // Get failed login count for this IP
      const failedLogins = await this.redis.getClient().incr(key);
      await this.redis.getClient().expire(key, Math.floor(windowMs / 1000));

      if (failedLogins >= this.alertThresholds.bruteForce) {
        await this.logSecurityEvent({
          type: 'brute_force_attack',
          ipAddress,
          userAgent,
          details: {
            failedLogins,
            threshold: this.alertThresholds.bruteForce,
            timeWindow: windowMs
          },
          timestamp: new Date(),
          severity: 'high'
        });

        // Generate critical security alert
        await this.generateSecurityAlert({
          type: 'brute_force_attack',
          severity: 'high',
          ipAddress,
          userAgent,
          details: { failedLogins, threshold: this.alertThresholds.bruteForce }
        });

        return true;
      }

      return false;
    } catch (error) {
      console.error('Failed to detect brute force attack:', error);
      return false;
    }
  }

  /**
   * Detect multiple IP access for same user
   */
  async detectMultipleIPAccess(userId: string, ipAddress: string, userAgent: string): Promise<boolean> {
    try {
      const key = `user_ips:${userId}`;
      const windowMs = 60 * 60 * 1000; // 1 hour window
      
      // Get current IPs for this user
      const ipsData = await this.redis.getClient().get(key);
      const ips = ipsData ? JSON.parse(ipsData) : [];
      
      // Add current IP if not already present
      if (!ips.includes(ipAddress)) {
        ips.push(ipAddress);
        await this.redis.getClient().setEx(
          key,
          Math.floor(windowMs / 1000),
          JSON.stringify(ips)
        );
      }

      if (ips.length >= this.alertThresholds.multipleIPs) {
        await this.logSecurityEvent({
          type: 'multiple_ip_access',
          ipAddress,
          userAgent,
          details: {
            userId,
            ipAddresses: ips,
            threshold: this.alertThresholds.multipleIPs,
            timeWindow: windowMs
          },
          timestamp: new Date(),
          severity: 'medium'
        });

        // Generate security alert
        await this.generateSecurityAlert({
          type: 'multiple_ip_access',
          severity: 'medium',
          ipAddress,
          userAgent,
          details: { userId, ipAddresses: ips, threshold: this.alertThresholds.multipleIPs }
        });

        return true;
      }

      return false;
    } catch (error) {
      console.error('Failed to detect multiple IP access:', error);
      return false;
    }
  }

  /**
   * Detect unusual access patterns
   */
  async detectUnusualAccessPattern(ipAddress: string, userAgent: string, endpoint: string): Promise<boolean> {
    try {
      const key = `access_pattern:${ipAddress}`;
      const windowMs = 10 * 60 * 1000; // 10 minutes window
      
      // Track requests per endpoint
      const patternData = await this.redis.getClient().get(key);
      const pattern = patternData ? JSON.parse(patternData) : { requests: 0, endpoints: {} };
      
      pattern.requests++;
      pattern.endpoints[endpoint] = (pattern.endpoints[endpoint] || 0) + 1;
      
      await this.redis.getClient().setEx(
        key,
        Math.floor(windowMs / 1000),
        JSON.stringify(pattern)
      );

      if (pattern.requests >= this.alertThresholds.unusualPattern) {
        await this.logSecurityEvent({
          type: 'unusual_access_pattern',
          ipAddress,
          userAgent,
          details: {
            requests: pattern.requests,
            endpoints: pattern.endpoints,
            threshold: this.alertThresholds.unusualPattern,
            timeWindow: windowMs
          },
          timestamp: new Date(),
          severity: 'medium'
        });

        // Generate security alert
        await this.generateSecurityAlert({
          type: 'unusual_access_pattern',
          severity: 'medium',
          ipAddress,
          userAgent,
          details: { requests: pattern.requests, endpoints: pattern.endpoints }
        });

        return true;
      }

      return false;
    } catch (error) {
      console.error('Failed to detect unusual access pattern:', error);
      return false;
    }
  }

  /**
   * Generate security alert and notify admin
   */
  async generateSecurityAlert(alertData: {
    type: SecurityEvent['type'];
    severity: SecurityEvent['severity'];
    ipAddress: string;
    userAgent: string;
    details: Record<string, any>;
  }): Promise<SecurityAlert> {
    try {
      const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      const alert: SecurityAlert = {
        id: alertId,
        type: alertData.type,
        severity: alertData.severity,
        message: this.generateAlertMessage(alertData.type, alertData.details),
        details: alertData.details,
        ipAddress: alertData.ipAddress,
        timestamp: new Date(),
        acknowledged: false
      };

      // Store alert in Redis for admin dashboard
      const alertKey = `security_alert:${alertId}`;
      await this.redis.getClient().setEx(
        alertKey,
        7 * 24 * 60 * 60, // 7 days
        JSON.stringify(alert)
      );

      // Add to active alerts list
      await this.redis.getClient().lPush('active_security_alerts', alertId);
      await this.redis.getClient().lTrim('active_security_alerts', 0, 99); // Keep last 100 alerts

      // Send immediate notification to admin for high/critical severity
      if (alertData.severity === 'high' || alertData.severity === 'critical') {
        await this.sendSecurityAlertNotification(alert);
      }

      // Log the alert generation
      await AuditLog.create({
        action: 'security_alert_generated',
        details: {
          alertId,
          alertType: alert.type,
          severity: alert.severity,
          message: alert.message
        },
        ipAddress: alertData.ipAddress,
        userAgent: alertData.userAgent,
        timestamp: new Date(),
        severity: 'warning'
      });

      return alert;
    } catch (error) {
      console.error('Failed to generate security alert:', error);
      throw error;
    }
  }

  /**
   * Generate human-readable alert message
   */
  private generateAlertMessage(type: SecurityEvent['type'], details: Record<string, any>): string {
    switch (type) {
      case 'brute_force_attack':
        return `Brute force attack detected: ${details.failedLogins} failed login attempts from IP ${details.ipAddress || 'unknown'}`;
      
      case 'suspicious_activity':
        return `Suspicious activity detected: ${details.activityCount} requests from IP ${details.ipAddress || 'unknown'} in the last hour`;
      
      case 'multiple_ip_access':
        return `User accessed from ${details.ipAddresses?.length || 0} different IP addresses within 1 hour`;
      
      case 'unusual_access_pattern':
        return `Unusual access pattern: ${details.requests} requests to multiple endpoints from same IP`;
      
      case 'account_lockout':
        return `Account locked due to ${details.failedAttempts} failed login attempts`;
      
      case 'rate_limit_exceeded':
        return `Rate limit exceeded for endpoint ${details.endpoint}`;
      
      default:
        return `Security event detected: ${type}`;
    }
  }

  /**
   * Send security alert notification to admin
   */
  private async sendSecurityAlertNotification(alert: SecurityAlert): Promise<void> {
    try {
      const subject = `🚨 Security Alert: ${alert.type.replace(/_/g, ' ').toUpperCase()}`;
      const message = `
Security Alert Details:
- Type: ${alert.type.replace(/_/g, ' ')}
- Severity: ${alert.severity.toUpperCase()}
- IP Address: ${alert.ipAddress}
- Time: ${alert.timestamp.toISOString()}
- Message: ${alert.message}

Please review the admin dashboard for more details.
      `.trim();

      await sendAdminNotification('security_alert', {
        subject,
        message,
        priority: alert.severity === 'critical' ? 'high' : 'normal',
        alertId: alert.id,
        alertType: alert.type,
        severity: alert.severity,
        ipAddress: alert.ipAddress
      });
    } catch (error) {
      console.error('Failed to send security alert notification:', error);
    }
  }

  /**
   * Get active security alerts
   */
  async getActiveSecurityAlerts(limit: number = 50): Promise<SecurityAlert[]> {
    try {
      const alertIds = await this.redis.getClient().lRange('active_security_alerts', 0, limit - 1);
      const alerts: SecurityAlert[] = [];

      for (const alertId of alertIds) {
        const alertData = await this.redis.getClient().get(`security_alert:${alertId}`);
        if (alertData) {
          alerts.push(JSON.parse(alertData));
        }
      }

      return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    } catch (error) {
      console.error('Failed to get active security alerts:', error);
      return [];
    }
  }

  /**
   * Acknowledge security alert
   */
  async acknowledgeSecurityAlert(alertId: string, adminId: string): Promise<boolean> {
    try {
      const alertKey = `security_alert:${alertId}`;
      const alertData = await this.redis.getClient().get(alertKey);
      
      if (!alertData) {
        return false;
      }

      const alert: SecurityAlert = JSON.parse(alertData);
      alert.acknowledged = true;

      await this.redis.getClient().setEx(
        alertKey,
        7 * 24 * 60 * 60, // 7 days
        JSON.stringify(alert)
      );

      // Log acknowledgment
      await AuditLog.create({
        action: 'security_alert_acknowledged',
        adminId,
        details: {
          alertId,
          alertType: alert.type,
          severity: alert.severity
        },
        timestamp: new Date(),
        severity: 'info'
      });

      return true;
    } catch (error) {
      console.error('Failed to acknowledge security alert:', error);
      return false;
    }
  }

  /**
   * Comprehensive security monitoring middleware
   */
  securityMonitoringMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const ipAddress = this.getClientIP(req);
        const userAgent = req.get('User-Agent') || 'Unknown';
        const endpoint = req.path;

        // Track request for IP analysis
        await this.trackRequest(ipAddress, userAgent, endpoint);

        // Detect various security threats
        await Promise.all([
          this.detectUnusualAccessPattern(ipAddress, userAgent, endpoint),
          this.detectSuspiciousActivity(ipAddress, userAgent)
        ]);

        next();
      } catch (error) {
        console.error('Security monitoring middleware error:', error);
        next(); // Continue on error to avoid blocking legitimate requests
      }
    };
  }

  /**
   * Track request for analysis
   */
  private async trackRequest(ipAddress: string, userAgent: string, endpoint: string): Promise<void> {
    try {
      // Update IP tracking
      const trackingKey = `ip_tracking:${ipAddress}`;
      const trackingData = await this.redis.getClient().get(trackingKey);
      const tracking = trackingData ? JSON.parse(trackingData) : {
        requestCount: 0,
        endpoints: [],
        userAgents: [],
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString()
      };

      tracking.requestCount++;
      tracking.lastSeen = new Date().toISOString();
      
      if (!tracking.endpoints.includes(endpoint)) {
        tracking.endpoints.push(endpoint);
      }
      
      if (!tracking.userAgents.includes(userAgent)) {
        tracking.userAgents.push(userAgent);
      }

      await this.redis.getClient().setEx(
        trackingKey,
        24 * 60 * 60, // 24 hours
        JSON.stringify(tracking)
      );
    } catch (error) {
      console.error('Failed to track request:', error);
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
        severity: event.severity === 'critical' || event.severity === 'high' ? 'warning' : 'info'
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
    bruteForceAttacks: number;
    multipleIPAccess: number;
    unusualPatterns: number;
    activeAlerts: number;
    topIPs: Array<{ ip: string; count: number; riskScore: number }>;
    alertsBySeverity: Record<string, number>;
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
        bruteForceAttacks: 0,
        multipleIPAccess: 0,
        unusualPatterns: 0,
        activeAlerts: 0,
        topIPs: [] as Array<{ ip: string; count: number; riskScore: number }>,
        alertsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
      };

      const ipCounts: Record<string, number> = {};

      for (const event of events) {
        // Count by event type
        switch (event.action) {
          case 'security_failed_login':
            report.failedLogins++;
            break;
          case 'security_rate_limit_exceeded':
            report.rateLimitExceeded++;
            break;
          case 'security_suspicious_activity':
            report.suspiciousActivity++;
            break;
          case 'security_account_lockout':
            report.accountLockouts++;
            break;
          case 'security_brute_force_attack':
            report.bruteForceAttacks++;
            break;
          case 'security_multiple_ip_access':
            report.multipleIPAccess++;
            break;
          case 'security_unusual_access_pattern':
            report.unusualPatterns++;
            break;
        }

        // Count by IP
        if (event.ipAddress && event.ipAddress !== 'unknown') {
          ipCounts[event.ipAddress] = (ipCounts[event.ipAddress] || 0) + 1;
        }
      }

      // Get active alerts
      const activeAlerts = await this.getActiveSecurityAlerts();
      report.activeAlerts = activeAlerts.filter(alert => !alert.acknowledged).length;

      // Count alerts by severity
      for (const alert of activeAlerts) {
        if (!alert.acknowledged) {
          report.alertsBySeverity[alert.severity]++;
        }
      }

      // Get top IPs with risk scores
      const topIPEntries = Object.entries(ipCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10);

      for (const [ip, count] of topIPEntries) {
        const analysis = await this.analyzeIPAddress(ip);
        report.topIPs.push({
          ip,
          count,
          riskScore: analysis.riskScore
        });
      }

      return report;
    } catch (error) {
      console.error('Failed to generate security report:', error);
      return {
        failedLogins: 0,
        rateLimitExceeded: 0,
        suspiciousActivity: 0,
        accountLockouts: 0,
        bruteForceAttacks: 0,
        multipleIPAccess: 0,
        unusualPatterns: 0,
        activeAlerts: 0,
        topIPs: [],
        alertsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
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