import { Request, Response } from 'express';
import { ApprovalRequest } from '../models/ApprovalRequest';
import { User } from '../models/User';
import { AuditLog } from '../models/AuditLog';
import { CryptoService } from '../services/cryptoService';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import { getSocketService } from '../services/socketService';
import mongoose from 'mongoose';

export class PasswordController {
  /**
   * Get secure password access for approved request
   * POST /api/password/access
   */
  static async getPasswordAccess(req: Request, res: Response): Promise<void> {
    try {
      const { requestId, accessToken } = req.body;
      const reqId = (req as AuthenticatedRequest).id || 'unknown';

      // Validate required fields
      if (!requestId || !accessToken) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request ID and access token are required',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Validate request ID format
      if (!mongoose.Types.ObjectId.isValid(requestId)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_REQUEST_ID',
            message: 'Invalid request ID format',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Find the approval request with access token
      const approvalRequest = await ApprovalRequest.findById(requestId).select('+accessToken');
      if (!approvalRequest) {
        // Log failed access attempt
        await AuditLog.create({
          action: 'password_access_failed',
          details: { 
            requestId,
            reason: 'Request not found',
            endpoint: req.path,
            method: req.method
          },
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || 'unknown',
          timestamp: new Date(),
          severity: 'warning'
        });

        res.status(404).json({
          success: false,
          error: {
            code: 'REQUEST_NOT_FOUND',
            message: 'Approval request not found',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Verify access token
      if (!approvalRequest.accessToken || approvalRequest.accessToken !== accessToken) {
        // Log failed access attempt
        await AuditLog.create({
          action: 'password_access_failed',
          userId: approvalRequest.userId,
          details: { 
            requestId,
            reason: 'Invalid access token',
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
            code: 'INVALID_ACCESS_TOKEN',
            message: 'Invalid or expired access token',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Check if access token is still valid
      if (!approvalRequest.isAccessTokenValid()) {
        // Log expired access attempt
        await AuditLog.create({
          action: 'password_access_failed',
          userId: approvalRequest.userId,
          details: { 
            requestId,
            reason: 'Access token expired',
            accessExpiresAt: approvalRequest.accessExpiresAt,
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
            code: 'ACCESS_TOKEN_EXPIRED',
            message: 'Access token has expired',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Get user and password
      const user = await User.findById(approvalRequest.userId);
      if (!user) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Generate session token for clipboard access
      const cryptoService = new CryptoService();
      const sessionResult = cryptoService.generateSecureSessionToken(60); // 60 minutes
      
      // Generate masked password for display (if needed)
      const maskedPassword = CryptoService.maskPassword(user.encryptedPassword);

      // Log successful password access
      await AuditLog.create({
        action: 'password_accessed',
        userId: approvalRequest.userId,
        details: { 
          requestId,
          sessionToken: sessionResult.token,
          sessionExpiresAt: sessionResult.expiresAt,
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      // Send real-time notification to user about password access
      try {
        const socketService = getSocketService();
        socketService.notifyUser(approvalRequest.userEmail, 'password-accessed', {
          requestId,
          sessionExpiresAt: sessionResult.expiresAt,
          accessedAt: new Date()
        });

        // Notify admins about password access
        socketService.notifyAdmins('password-accessed', {
          requestId,
          userEmail: approvalRequest.userEmail,
          accessedAt: new Date(),
          sessionExpiresAt: sessionResult.expiresAt
        });
      } catch (socketError) {
        console.error('Failed to send real-time password access notification:', socketError);
      }

      res.status(200).json({
        success: true,
        data: {
          sessionToken: sessionResult.token,
          sessionExpiresAt: sessionResult.expiresAt,
          maskedPassword,
          userEmail: approvalRequest.userEmail,
          accessExpiresAt: approvalRequest.accessExpiresAt
        },
        timestamp: new Date().toISOString(),
        requestId: reqId
      });

    } catch (error) {
      console.error('Password access error:', error);

      // Log system error
      await AuditLog.create({
        action: 'password_access_error',
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
          code: 'INTERNAL_ERROR',
          message: 'Failed to access password',
          timestamp: new Date().toISOString(),
          requestId: (req as AuthenticatedRequest).id || 'unknown'
        }
      });
    }
  }

  /**
   * Trigger clipboard copy functionality
   * POST /api/password/copy
   */
  static async copyToClipboard(req: Request, res: Response): Promise<void> {
    try {
      const { sessionToken } = req.body;
      const reqId = (req as AuthenticatedRequest).id || 'unknown';

      // Validate required fields
      if (!sessionToken) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Session token is required',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Validate session token
      const isValidSession = CryptoService.validateSessionToken(sessionToken);
      if (!isValidSession) {
        // Log failed clipboard access attempt
        await AuditLog.create({
          action: 'clipboard_access_failed',
          details: { 
            reason: 'Invalid session token',
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
            code: 'INVALID_SESSION_TOKEN',
            message: 'Invalid or expired session token',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Find the approval request associated with this session
      // Note: In a real implementation, you'd store session-to-request mapping
      // For now, we'll find the most recent approved request
      const approvalRequest = await ApprovalRequest.findOne({
        status: 'approved',
        accessExpiresAt: { $gt: new Date() }
      }).sort({ respondedAt: -1 });

      if (!approvalRequest) {
        res.status(404).json({
          success: false,
          error: {
            code: 'NO_VALID_REQUEST',
            message: 'No valid approved request found',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Get user and decrypt password
      const user = await User.findById(approvalRequest.userId);
      if (!user) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found',
            timestamp: new Date().toISOString(),
            requestId: reqId
          }
        });
        return;
      }

      // Decrypt the password for clipboard copy
      const cryptoService = new CryptoService();
      const decryptedPassword = cryptoService.decryptPassword(user.encryptedPassword);

      // Log clipboard copy action
      await AuditLog.create({
        action: 'password_copied_to_clipboard',
        userId: approvalRequest.userId,
        details: { 
          requestId: approvalRequest._id,
          sessionToken,
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      // Send real-time notification about clipboard copy
      try {
        const socketService = getSocketService();
        socketService.notifyUser(approvalRequest.userEmail, 'password-copied', {
          requestId: approvalRequest._id,
          copiedAt: new Date(),
          clearAfterSeconds: 60
        });

        // Notify admins about clipboard copy
        socketService.notifyAdmins('password-copied', {
          requestId: approvalRequest._id,
          userEmail: approvalRequest.userEmail,
          copiedAt: new Date()
        });
      } catch (socketError) {
        console.error('Failed to send real-time clipboard copy notification:', socketError);
      }

      // Return the actual password for clipboard copy
      // Note: This should be handled securely on the client side
      res.status(200).json({
        success: true,
        data: {
          password: decryptedPassword,
          userEmail: approvalRequest.userEmail,
          copyInstructions: 'Password will be automatically cleared from clipboard in 60 seconds'
        },
        timestamp: new Date().toISOString(),
        requestId: reqId
      });

    } catch (error) {
      console.error('Clipboard copy error:', error);

      // Log system error
      await AuditLog.create({
        action: 'clipboard_copy_error',
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
          code: 'INTERNAL_ERROR',
          message: 'Failed to copy password to clipboard',
          timestamp: new Date().toISOString(),
          requestId: (req as AuthenticatedRequest).id || 'unknown'
        }
      });
    }
  }
}