import { Router } from 'express';
import { 
  loginAdmin, 
  logoutAdmin, 
  getAdminProfile, 
  updateNotificationPreferences, 
  getNotificationPreferences,
  setupAdmin,
  getSecurityReport,
  getSecurityAlerts,
  acknowledgeSecurityAlert,
  analyzeIPAddress,
  getAuditLogs,
  getAuditLogStats,
  cleanupAuditLogs,
  verifyAuditLogIntegrity
} from '../controllers/adminController';
import { 
  authenticateAdmin, 
  addRequestId, 
  logApiAccess,
  requireAdminPermission 
} from '../middleware/authMiddleware';
import rateLimit from 'express-rate-limit';

const router = Router();

// Rate limiting for auth endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts. Please try again later.',
      timestamp: new Date().toISOString()
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for general admin endpoints
const adminRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please try again later.',
      timestamp: new Date().toISOString()
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply middleware to all routes
router.use(addRequestId);
router.use(adminRateLimit);

/**
 * @route   POST /api/admin/setup
 * @desc    Create initial admin account (only works if no admin exists)
 * @access  Public (but only works once)
 */
router.post('/setup', authRateLimit, setupAdmin);

/**
 * @route   POST /api/admin/login
 * @desc    Admin login
 * @access  Public
 */
router.post('/login', authRateLimit, loginAdmin);

/**
 * @route   POST /api/admin/logout
 * @desc    Admin logout
 * @access  Private (Admin)
 */
router.post('/logout', authenticateAdmin, logApiAccess, logoutAdmin);

/**
 * @route   GET /api/admin/profile
 * @desc    Get admin profile
 * @access  Private (Admin)
 */
router.get('/profile', authenticateAdmin, logApiAccess, getAdminProfile);

/**
 * @route   GET /api/admin/notification-preferences
 * @desc    Get notification preferences
 * @access  Private (Admin)
 */
router.get(
  '/notification-preferences', 
  authenticateAdmin, 
  logApiAccess,
  requireAdminPermission('read:preferences'),
  getNotificationPreferences
);

/**
 * @route   PUT /api/admin/notification-preferences
 * @desc    Update notification preferences
 * @access  Private (Admin)
 */
router.put(
  '/notification-preferences', 
  authenticateAdmin, 
  logApiAccess,
  requireAdminPermission('update:preferences'),
  updateNotificationPreferences
);

/**
 * @route   GET /api/admin/security/report
 * @desc    Get security monitoring report
 * @access  Private (Admin)
 */
router.get(
  '/security/report',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:security'),
  getSecurityReport
);

/**
 * @route   GET /api/admin/security/alerts
 * @desc    Get security alerts
 * @access  Private (Admin)
 */
router.get(
  '/security/alerts',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:security'),
  getSecurityAlerts
);

/**
 * @route   PUT /api/admin/security/alerts/:alertId/acknowledge
 * @desc    Acknowledge security alert
 * @access  Private (Admin)
 */
router.put(
  '/security/alerts/:alertId/acknowledge',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('update:security'),
  acknowledgeSecurityAlert
);

/**
 * @route   GET /api/admin/security/ip/:ipAddress
 * @desc    Analyze IP address for security risks
 * @access  Private (Admin)
 */
router.get(
  '/security/ip/:ipAddress',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:security'),
  analyzeIPAddress
);

/**
 * @route   GET /api/admin/audit/logs
 * @desc    Get audit logs with search and filtering
 * @access  Private (Admin)
 */
router.get(
  '/audit/logs',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:audit'),
  getAuditLogs
);

/**
 * @route   GET /api/admin/audit/stats
 * @desc    Get audit log statistics
 * @access  Private (Admin)
 */
router.get(
  '/audit/stats',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:audit'),
  getAuditLogStats
);

/**
 * @route   DELETE /api/admin/audit/cleanup
 * @desc    Cleanup old audit logs (retention policy)
 * @access  Private (Admin)
 */
router.delete(
  '/audit/cleanup',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('delete:audit'),
  cleanupAuditLogs
);

/**
 * @route   GET /api/admin/audit/integrity
 * @desc    Verify audit log integrity
 * @access  Private (Admin)
 */
router.get(
  '/audit/integrity',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('read:audit'),
  verifyAuditLogIntegrity
);

export default router;