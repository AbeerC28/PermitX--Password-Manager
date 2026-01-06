import { Router } from 'express';
import { PasswordController } from '../controllers/passwordController';
import { addRequestId } from '../middleware/authMiddleware';

const router = Router();

/**
 * POST /api/password/access
 * Get secure password access for approved request
 * Requires valid access token from approved request
 * Body parameters:
 * - requestId: string (required) - ID of the approved request
 * - accessToken: string (required) - Access token from approval
 */
router.post(
  '/access',
  addRequestId,
  PasswordController.getPasswordAccess
);

/**
 * POST /api/password/copy
 * Trigger clipboard copy functionality
 * Requires valid session token
 * Body parameters:
 * - sessionToken: string (required) - Session token from password access
 */
router.post(
  '/copy',
  addRequestId,
  PasswordController.copyToClipboard
);

export default router;