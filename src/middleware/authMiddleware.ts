import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/authService';
import { securityService } from '../services/securityService';
import { AuditLog } from '../models/AuditLog';

// Extend Request interface to include admin data
export interface AuthenticatedRequest extends Request {
  admin?: {
    adminId: string;
    username: string;
    email: string;
    sessionId: string;
  };
  id?: string; // Request ID for tracking
}

/**
 * Middleware to authenticate admin requests using JWT tokens
 */
export const authenticateAdmin = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Generate request ID for tracking
    req.id = generateRequestId();

    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        error: {
          code: 'MISSING_TOKEN',
          message: 'Authorization token is required',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Validate token and get session data
    const validation = await authService.validateToken(token);
    
    if (!validation.valid || !validation.payload || !validation.session) {
      // Record failed authentication for security monitoring
      await securityService.recordFailedLogin(
        validation.payload?.username || 'unknown',
        req.ip || 'unknown',
        req.get('User-Agent') || 'unknown'
      );

      // Log failed authentication attempt
      await AuditLog.create({
        action: 'admin_auth_failed',
        details: { 
          reason: 'Invalid or expired token',
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'warning'
      });

      res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired authorization token',
          timestamp: new Date().toISOString(),
          requestId: req.id
        }
      });
      return;
    }

    // Clear failed login attempts on successful authentication
    await securityService.clearFailedLogins(validation.payload.username);

    // Attach admin data to request
    req.admin = {
      adminId: validation.payload.adminId,
      username: validation.payload.username,
      email: validation.payload.email,
      sessionId: validation.payload.sessionId
    };

    // Continue to next middleware
    next();

  } catch (error) {
    console.error('Authentication middleware error:', error);

    // Log system error
    await AuditLog.create({
      action: 'admin_auth_error',
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error',
        endpoint: req.path,
        method: req.method
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'error'
    });

    res.status(500).json({
      success: false,
      error: {
        code: 'AUTH_ERROR',
        message: 'Authentication system error',
        timestamp: new Date().toISOString(),
        requestId: req.id || 'unknown'
      }
    });
  }
};

/**
 * Optional authentication middleware - doesn't fail if no token provided
 * Useful for endpoints that work for both authenticated and unauthenticated users
 */
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Generate request ID for tracking
    req.id = generateRequestId();

    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token provided, continue without authentication
      next();
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Validate token and get session data
    const validation = await authService.validateToken(token);
    
    if (validation.valid && validation.payload && validation.session) {
      // Attach admin data to request if valid
      req.admin = {
        adminId: validation.payload.adminId,
        username: validation.payload.username,
        email: validation.payload.email,
        sessionId: validation.payload.sessionId
      };
    }

    // Continue regardless of token validity
    next();

  } catch (error) {
    console.error('Optional authentication middleware error:', error);
    // Continue even if there's an error
    next();
  }
};

/**
 * Middleware to add request ID to all requests
 */
export const addRequestId = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  req.id = generateRequestId();
  next();
};

/**
 * Generate unique request ID for tracking
 */
function generateRequestId(): string {
  const timestamp = Date.now().toString(36);
  const randomBytes = Math.random().toString(36).substring(2);
  return `req-${timestamp}-${randomBytes}`;
}

/**
 * Middleware to validate admin permissions for specific actions
 */
export const requireAdminPermission = (permission: string) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.admin) {
        res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_REQUIRED',
            message: 'Admin authentication is required',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
        return;
      }

      // For now, all authenticated admins have all permissions
      // In a more complex system, you would check specific permissions here
      // based on the admin's role or permission set

      // Log permission check
      await AuditLog.create({
        action: 'permission_checked',
        adminId: req.admin.adminId,
        details: { 
          permission,
          endpoint: req.path,
          method: req.method,
          granted: true
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      next();

    } catch (error) {
      console.error('Permission check error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'PERMISSION_ERROR',
          message: 'Permission check failed',
          timestamp: new Date().toISOString(),
          requestId: req.id || 'unknown'
        }
      });
    }
  };
};

/**
 * Middleware to log API access
 */
export const logApiAccess = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Log API access
    await AuditLog.create({
      action: 'api_access',
      adminId: req.admin?.adminId,
      details: { 
        endpoint: req.path,
        method: req.method,
        query: req.query,
        authenticated: !!req.admin
      },
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      severity: 'info'
    });

    next();

  } catch (error) {
    console.error('API access logging error:', error);
    // Continue even if logging fails
    next();
  }
};