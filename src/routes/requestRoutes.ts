import { Router } from 'express';
import { RequestController } from '../controllers/requestController';
import { authenticateAdmin, requireAdminPermission, logApiAccess, optionalAuth, addRequestId } from '../middleware/authMiddleware';

const router = Router();

/**
 * POST /api/requests
 * Create a new password request
 * Public endpoint - no authentication required
 * Users can request password access by providing their email
 */
router.post(
  '/',
  addRequestId,
  RequestController.createRequest
);

/**
 * GET /api/requests/status/:id
 * Get request status by ID
 * Public endpoint - no authentication required
 * Users can check the status of their password request
 */
router.get(
  '/status/:id',
  addRequestId,
  RequestController.getRequestStatus
);

/**
 * GET /api/requests
 * Get all requests (admin only)
 * Requires admin authentication and request read permission
 * Query parameters:
 * - status: string - filter by status (pending, approved, denied, expired)
 * - limit: number - number of requests to return (default: 50)
 * - offset: number - number of requests to skip (default: 0)
 */
router.get(
  '/',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('request:read'),
  RequestController.getAllRequests
);

/**
 * PUT /api/requests/:id/approve
 * Approve a password request
 * Requires admin authentication and request approve permission
 * Body parameters:
 * - reason: string (optional) - reason for approval
 */
router.put(
  '/:id/approve',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('request:approve'),
  RequestController.approveRequest
);

/**
 * PUT /api/requests/:id/deny
 * Deny a password request
 * Requires admin authentication and request deny permission
 * Body parameters:
 * - reason: string (required) - reason for denial
 */
router.put(
  '/:id/deny',
  authenticateAdmin,
  logApiAccess,
  requireAdminPermission('request:deny'),
  RequestController.denyRequest
);

export default router;