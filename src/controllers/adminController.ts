import { Response } from 'express';
import { Admin, adminValidationSchema } from '../models/Admin';
import { AuditLog } from '../models/AuditLog';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import { authService } from '../services/authService';
import { notificationScheduler } from '../services/notificationSchedulerService';

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