import { Router } from 'express';
import { 
  loginAdmin, 
  logoutAdmin, 
  getAdminProfile, 
  updateNotificationPreferences, 
  getNotificationPreferences,
  setupAdmin 
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

export default router;