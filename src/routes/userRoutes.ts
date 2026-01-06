import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authenticateAdmin, requireAdminPermission, logApiAccess } from '../middleware/authMiddleware';

const router = Router();

// Apply authentication and logging middleware to all user routes
router.use(authenticateAdmin);
router.use(logApiAccess);

/**
 * POST /api/users
 * Create a new user
 * Requires admin authentication and user management permission
 */
router.post(
  '/',
  requireAdminPermission('user:create'),
  UserController.createUser
);

/**
 * GET /api/users
 * Get all users
 * Requires admin authentication and user read permission
 * Query parameters:
 * - includeInactive: boolean - whether to include inactive users
 */
router.get(
  '/',
  requireAdminPermission('user:read'),
  UserController.getAllUsers
);

/**
 * PUT /api/users/:id
 * Update user (primarily for password updates)
 * Requires admin authentication and user update permission
 */
router.put(
  '/:id',
  requireAdminPermission('user:update'),
  UserController.updateUser
);

/**
 * DELETE /api/users/:id
 * Delete a user
 * Requires admin authentication and user delete permission
 */
router.delete(
  '/:id',
  requireAdminPermission('user:delete'),
  UserController.deleteUser
);

export default router;