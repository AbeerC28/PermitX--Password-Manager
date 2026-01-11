import { Response } from 'express';
import { Admin, adminValidationSchema } from '../models/Admin';
import { AuditLog } from '../models/AuditLog';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import { authService } from '../services/authService';
import { notificationScheduler } from '../services/notificationSchedulerService';
import { securityService } from '../services/securityService';

/**
 * Admin login
 * POST /api/admin/login
 */
export const loginAdmin = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_CREDENTIALS',
          message: 'Username and password are required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Authenticate admin
    const admin = await Admin.authenticateAdmin(username, password);
    if (!admin) {
      // Log failed login attempt
      await AuditLog.create({
        action: 'admin_login_failed',
        details: { 
          username,
          reason: 'Invalid credentials'
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'warning'
      });

      res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid username or password',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Create session and generate token
    const loginResult = await authService.login(admin.username, password, req.ip || 'unknown', req.get('User-Agent') || 'unknown');
    
    if (!loginResult.success || !loginResult.token || !loginResult.sessionId) {
      res.status(500).json({
        success: false,
        error: {
          code: 'SESSION_ERROR',
          message: 'Failed to create session',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Update admin activity in notification scheduler
    notificationScheduler.updateAdminActivity();

    // Log successful login
    await AuditLog.create({
      action: 'admin_login_success',
      adminId: admin._id,
      details: { 
        username: admin.username,
        sessionId: loginResult.sessionId
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        admin: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          notificationPreferences: admin.notificationPreferences,
          lastLogin: admin.lastLogin
        },
        token: loginResult.token,
        sessionId: loginResult.sessionId
      },
      message: 'Login successful',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Admin login error:', error);

    await AuditLog.create({
      action: 'admin_login_error',
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error'
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'LOGIN_ERROR',
        message: 'Login failed due to server error',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Admin logout
 * POST /api/admin/logout
 */
export const logoutAdmin = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Invalidate session
    await authService.logout(req.admin.sessionId, req.ip || 'unknown', req.get('User-Agent') || 'unknown');

    // Log logout
    await AuditLog.create({
      action: 'admin_logout',
      adminId: req.admin.adminId,
      details: { 
        username: req.admin.username,
        sessionId: req.admin.sessionId
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      message: 'Logout successful',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Admin logout error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'LOGOUT_ERROR',
        message: 'Logout failed due to server error',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get admin profile
 * GET /api/admin/profile
 */
export const getAdminProfile = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Get admin details
    const admin = await Admin.getAdminById(req.admin.adminId);
    if (!admin) {
      res.status(404).json({
        success: false,
        error: {
          code: 'ADMIN_NOT_FOUND',
          message: 'Admin profile not found',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    res.status(200).json({
      success: true,
      data: {
        admin: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          notificationPreferences: admin.notificationPreferences,
          lastLogin: admin.lastLogin,
          createdAt: admin.createdAt
        }
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get admin profile error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'PROFILE_ERROR',
        message: 'Failed to retrieve admin profile',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Update notification preferences
 * PUT /api/admin/notification-preferences
 */
export const updateNotificationPreferences = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Validate input
    const { error, value } = adminValidationSchema.notificationPreferences.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: error.details[0].message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Get admin
    const admin = await Admin.getAdminById(req.admin.adminId);
    if (!admin) {
      res.status(404).json({
        success: false,
        error: {
          code: 'ADMIN_NOT_FOUND',
          message: 'Admin not found',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Store old preferences for audit log
    const oldPreferences = { ...admin.notificationPreferences };

    // Update notification preferences
    await admin.updateNotificationPreferences(value);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Log preference update
    await AuditLog.create({
      action: 'notification_preferences_updated',
      adminId: req.admin.adminId,
      details: { 
        oldPreferences,
        newPreferences: admin.notificationPreferences,
        changes: value
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        notificationPreferences: admin.notificationPreferences
      },
      message: 'Notification preferences updated successfully',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Update notification preferences error:', error);

    await AuditLog.create({
      action: 'notification_preferences_update_error',
      adminId: req.admin?.adminId,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        requestBody: req.body
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'UPDATE_ERROR',
        message: 'Failed to update notification preferences',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get notification preferences
 * GET /api/admin/notification-preferences
 */
export const getNotificationPreferences = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Get admin
    const admin = await Admin.getAdminById(req.admin.adminId);
    if (!admin) {
      res.status(404).json({
        success: false,
        error: {
          code: 'ADMIN_NOT_FOUND',
          message: 'Admin not found',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    res.status(200).json({
      success: true,
      data: {
        notificationPreferences: admin.notificationPreferences
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get notification preferences error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'GET_PREFERENCES_ERROR',
        message: 'Failed to retrieve notification preferences',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Create initial admin (for setup)
 * POST /api/admin/setup
 */
export const setupAdmin = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    // Check if admin already exists
    const existingAdmin = await Admin.findOne({});
    if (existingAdmin) {
      res.status(409).json({
        success: false,
        error: {
          code: 'ADMIN_EXISTS',
          message: 'Admin already exists. Use login instead.',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { username, password, email, notificationPreferences } = req.body;

    // Create admin
    const admin = await Admin.createAdmin({
      username,
      password,
      email,
      notificationPreferences
    });

    // Log admin creation
    await AuditLog.create({
      action: 'admin_created',
      adminId: admin._id,
      details: { 
        username: admin.username,
        email: admin.email,
        notificationPreferences: admin.notificationPreferences
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(201).json({
      success: true,
      data: {
        admin: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          notificationPreferences: admin.notificationPreferences
        }
      },
      message: 'Admin created successfully',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Setup admin error:', error);

    await AuditLog.create({
      action: 'admin_setup_error',
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error'
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'SETUP_ERROR',
        message: error instanceof Error ? error.message : 'Failed to create admin',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get security report
 * GET /api/admin/security/report
 */
export const getSecurityReport = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const hours = parseInt(req.query.hours as string) || 24;
    
    if (hours < 1 || hours > 168) { // Max 1 week
      res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_HOURS',
          message: 'Hours must be between 1 and 168',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const report = await securityService.generateSecurityReport(hours);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Log security report access
    await AuditLog.create({
      action: 'security_report_accessed',
      adminId: req.admin.adminId,
      details: { 
        reportHours: hours,
        reportSummary: {
          totalEvents: report.failedLogins + report.rateLimitExceeded + report.suspiciousActivity + report.accountLockouts,
          activeAlerts: report.activeAlerts
        }
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        report,
        generatedAt: new Date().toISOString(),
        timeRange: `${hours} hours`
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get security report error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'SECURITY_REPORT_ERROR',
        message: 'Failed to generate security report',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get security alerts
 * GET /api/admin/security/alerts
 */
export const getSecurityAlerts = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const limit = parseInt(req.query.limit as string) || 50;
    const includeAcknowledged = req.query.includeAcknowledged === 'true';

    if (limit < 1 || limit > 100) {
      res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_LIMIT',
          message: 'Limit must be between 1 and 100',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const alerts = await securityService.getActiveSecurityAlerts(limit);
    
    // Filter out acknowledged alerts if not requested
    const filteredAlerts = includeAcknowledged 
      ? alerts 
      : alerts.filter(alert => !alert.acknowledged);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Log security alerts access
    await AuditLog.create({
      action: 'security_alerts_accessed',
      adminId: req.admin.adminId,
      details: { 
        alertCount: filteredAlerts.length,
        includeAcknowledged,
        limit
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        alerts: filteredAlerts,
        totalCount: filteredAlerts.length,
        includeAcknowledged
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get security alerts error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'SECURITY_ALERTS_ERROR',
        message: 'Failed to retrieve security alerts',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Acknowledge security alert
 * PUT /api/admin/security/alerts/:alertId/acknowledge
 */
export const acknowledgeSecurityAlert = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { alertId } = req.params;

    if (!alertId) {
      res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_ALERT_ID',
          message: 'Alert ID is required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const success = await securityService.acknowledgeSecurityAlert(alertId, req.admin.adminId);

    if (!success) {
      res.status(404).json({
        success: false,
        error: {
          code: 'ALERT_NOT_FOUND',
          message: 'Security alert not found',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    res.status(200).json({
      success: true,
      message: 'Security alert acknowledged successfully',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Acknowledge security alert error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'ACKNOWLEDGE_ALERT_ERROR',
        message: 'Failed to acknowledge security alert',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Analyze IP address
 * GET /api/admin/security/ip/:ipAddress
 */
export const analyzeIPAddress = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { ipAddress } = req.params;

    if (!ipAddress) {
      res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_IP_ADDRESS',
          message: 'IP address is required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const analysis = await securityService.analyzeIPAddress(ipAddress);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Log IP analysis access
    await AuditLog.create({
      action: 'ip_analysis_accessed',
      adminId: req.admin.adminId,
      details: { 
        analyzedIP: ipAddress,
        riskScore: analysis.riskScore,
        requestCount: analysis.requestCount
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        analysis
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Analyze IP address error:', error);

    res.status(500).json({
      success: false,
      error: {
        code: 'IP_ANALYSIS_ERROR',
        message: 'Failed to analyze IP address',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get audit logs with meta-audit logging
 * GET /api/admin/audit/logs
 */
export const getAuditLogs = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Parse query parameters
    const {
      action,
      userId,
      adminId,
      severity,
      startDate,
      endDate,
      ipAddress,
      limit = '100',
      offset = '0'
    } = req.query;

    // Validate and convert parameters
    const searchCriteria: any = {
      limit: Math.min(parseInt(limit as string) || 100, 1000), // Max 1000 records
      offset: Math.max(parseInt(offset as string) || 0, 0)
    };

    if (action) searchCriteria.action = action as string;
    if (userId) searchCriteria.userId = userId as string;
    if (adminId) searchCriteria.adminId = adminId as string;
    if (severity) searchCriteria.severity = severity as string;
    if (startDate) searchCriteria.startDate = new Date(startDate as string);
    if (endDate) searchCriteria.endDate = new Date(endDate as string);
    if (ipAddress) searchCriteria.ipAddress = ipAddress as string;

    // Search audit logs
    const result = await AuditLog.searchLogs(searchCriteria);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Meta-audit logging: Log the audit access itself
    await AuditLog.create({
      action: 'audit_logs_accessed',
      adminId: req.admin.adminId,
      details: { 
        searchCriteria: {
          action: searchCriteria.action,
          userId: searchCriteria.userId,
          adminId: searchCriteria.adminId,
          severity: searchCriteria.severity,
          startDate: searchCriteria.startDate?.toISOString(),
          endDate: searchCriteria.endDate?.toISOString(),
          ipAddress: searchCriteria.ipAddress,
          limit: searchCriteria.limit,
          offset: searchCriteria.offset
        },
        resultCount: result.total,
        returnedCount: result.logs.length
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        logs: result.logs,
        pagination: {
          total: result.total,
          limit: searchCriteria.limit,
          offset: searchCriteria.offset,
          hasMore: result.total > (searchCriteria.offset + result.logs.length)
        }
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get audit logs error:', error);

    // Log the error access attempt
    await AuditLog.create({
      action: 'audit_logs_access_error',
      adminId: req.admin?.adminId,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        queryParams: req.query
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'AUDIT_LOGS_ERROR',
        message: 'Failed to retrieve audit logs',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Get audit log statistics
 * GET /api/admin/audit/stats
 */
export const getAuditLogStats = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { startDate, endDate } = req.query;

    const searchStartDate = startDate ? new Date(startDate as string) : undefined;
    const searchEndDate = endDate ? new Date(endDate as string) : undefined;

    // Get audit log statistics
    const stats = await AuditLog.getLogStats(searchStartDate, searchEndDate);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Meta-audit logging: Log the stats access
    await AuditLog.create({
      action: 'audit_stats_accessed',
      adminId: req.admin.adminId,
      details: { 
        dateRange: {
          startDate: searchStartDate?.toISOString(),
          endDate: searchEndDate?.toISOString()
        },
        statsReturned: {
          totalLogs: stats.totalLogs,
          severityCount: Object.keys(stats.logsBySeverity).length,
          actionCount: Object.keys(stats.logsByAction).length
        }
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        stats,
        dateRange: {
          startDate: searchStartDate?.toISOString(),
          endDate: searchEndDate?.toISOString()
        }
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Get audit log stats error:', error);

    // Log the error access attempt
    await AuditLog.create({
      action: 'audit_stats_access_error',
      adminId: req.admin?.adminId,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        queryParams: req.query
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'AUDIT_STATS_ERROR',
        message: 'Failed to retrieve audit log statistics',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Cleanup old audit logs (retention policy)
 * DELETE /api/admin/audit/cleanup
 */
export const cleanupAuditLogs = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { retentionDays = '90' } = req.body;
    const retentionDaysNum = parseInt(retentionDays);

    if (retentionDaysNum < 30 || retentionDaysNum > 365) {
      res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_RETENTION_DAYS',
          message: 'Retention days must be between 30 and 365',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Perform cleanup
    const deletedCount = await AuditLog.cleanupOldLogs(retentionDaysNum);

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Meta-audit logging: Log the cleanup operation
    await AuditLog.create({
      action: 'audit_logs_cleanup',
      adminId: req.admin.adminId,
      details: { 
        retentionDays: retentionDaysNum,
        deletedCount,
        cutoffDate: new Date(Date.now() - retentionDaysNum * 24 * 60 * 60 * 1000).toISOString()
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'warning'
    });

    res.status(200).json({
      success: true,
      data: {
        deletedCount,
        retentionDays: retentionDaysNum,
        cutoffDate: new Date(Date.now() - retentionDaysNum * 24 * 60 * 60 * 1000).toISOString()
      },
      message: `Successfully cleaned up ${deletedCount} old audit log entries`,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Cleanup audit logs error:', error);

    // Log the error
    await AuditLog.create({
      action: 'audit_logs_cleanup_error',
      adminId: req.admin?.adminId,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        requestBody: req.body
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'AUDIT_CLEANUP_ERROR',
        message: 'Failed to cleanup audit logs',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Verify audit log integrity
 * GET /api/admin/audit/integrity
 */
export const verifyAuditLogIntegrity = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Admin authentication required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const { startDate, endDate, sampleSize = '1000' } = req.query;
    const sampleSizeNum = Math.min(parseInt(sampleSize as string) || 1000, 10000);

    // Build query for integrity check
    const query: any = {};
    if (startDate) query.timestamp = { $gte: new Date(startDate as string) };
    if (endDate) {
      if (!query.timestamp) query.timestamp = {};
      query.timestamp.$lte = new Date(endDate as string);
    }

    // Get sample of audit logs for integrity verification
    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .limit(sampleSizeNum)
      .lean();

    // Perform integrity checks
    const integrityReport = {
      totalChecked: logs.length,
      issues: [] as Array<{
        logId: string;
        issue: string;
        severity: 'low' | 'medium' | 'high';
        details: any;
      }>,
      summary: {
        missingFields: 0,
        invalidTimestamps: 0,
        suspiciousPatterns: 0,
        dataInconsistencies: 0
      }
    };

    const now = new Date();
    const requiredFields = ['action', 'ipAddress', 'userAgent', 'timestamp'];

    for (const log of logs) {
      // Check for missing required fields
      for (const field of requiredFields) {
        if (!(log as any)[field]) {
          integrityReport.issues.push({
            logId: log._id.toString(),
            issue: `Missing required field: ${field}`,
            severity: 'high',
            details: { field, logAction: log.action }
          });
          integrityReport.summary.missingFields++;
        }
      }

      // Check for invalid timestamps
      if (log.timestamp > now) {
        integrityReport.issues.push({
          logId: log._id.toString(),
          issue: 'Future timestamp detected',
          severity: 'high',
          details: { timestamp: log.timestamp, logAction: log.action }
        });
        integrityReport.summary.invalidTimestamps++;
      }

      // Check for suspicious patterns (e.g., identical logs within seconds)
      const duplicateCheck = logs.filter(l => 
        l._id.toString() !== log._id.toString() &&
        l.action === log.action &&
        l.ipAddress === log.ipAddress &&
        Math.abs(new Date(l.timestamp).getTime() - new Date(log.timestamp).getTime()) < 1000
      );

      if (duplicateCheck.length > 0) {
        integrityReport.issues.push({
          logId: log._id.toString(),
          issue: 'Potential duplicate log entries',
          severity: 'medium',
          details: { 
            duplicateCount: duplicateCheck.length,
            logAction: log.action,
            timestamp: log.timestamp
          }
        });
        integrityReport.summary.suspiciousPatterns++;
      }

      // Check for data inconsistencies
      if (log.severity && !['info', 'warning', 'error'].includes(log.severity)) {
        integrityReport.issues.push({
          logId: log._id.toString(),
          issue: 'Invalid severity level',
          severity: 'medium',
          details: { severity: log.severity, logAction: log.action }
        });
        integrityReport.summary.dataInconsistencies++;
      }
    }

    // Calculate integrity score
    const totalIssues = integrityReport.issues.length;
    const integrityScore = Math.max(0, 100 - (totalIssues / integrityReport.totalChecked * 100));

    // Update admin activity
    notificationScheduler.updateAdminActivity();

    // Meta-audit logging: Log the integrity check
    await AuditLog.create({
      action: 'audit_integrity_check',
      adminId: req.admin.adminId,
      details: { 
        dateRange: {
          startDate: startDate ? new Date(startDate as string).toISOString() : undefined,
          endDate: endDate ? new Date(endDate as string).toISOString() : undefined
        },
        sampleSize: sampleSizeNum,
        totalChecked: integrityReport.totalChecked,
        totalIssues,
        integrityScore: Math.round(integrityScore * 100) / 100,
        issuesSummary: integrityReport.summary
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: totalIssues > 0 ? 'warning' : 'info'
    });

    res.status(200).json({
      success: true,
      data: {
        integrityReport,
        integrityScore: Math.round(integrityScore * 100) / 100,
        dateRange: {
          startDate: startDate ? new Date(startDate as string).toISOString() : undefined,
          endDate: endDate ? new Date(endDate as string).toISOString() : undefined
        }
      },
      timestamp: new Date().toISOString(),
      requestId: req.id
    });

  } catch (error) {
    console.error('Verify audit log integrity error:', error);

    // Log the error
    await AuditLog.create({
      action: 'audit_integrity_check_error',
      adminId: req.admin?.adminId,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        queryParams: req.query
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'AUDIT_INTEGRITY_ERROR',
        message: 'Failed to verify audit log integrity',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};