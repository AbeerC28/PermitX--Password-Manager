import { Request, Response } from 'express';
import { ApprovalRequest } from '../models/ApprovalRequest';
import { User } from '../models/User';
import { AuditLog } from '../models/AuditLog';
import { AuthenticatedRequest } from '../middleware/authMiddleware';
import mongoose from 'mongoose';

export class RequestController {
  /**
   * Create a new password request
   * POST /api/requests
   */
  static async createRequest(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;
      const requestId = (req as AuthenticatedRequest).id || 'unknown';

      // Validate required fields
      if (!email) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Email is required',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_EMAIL',
            message: 'Please provide a valid email address',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Find user by email
      const user = await User.getUserByEmail(email);
      if (!user) {
        // Log failed attempt for security monitoring
        await AuditLog.create({
          action: 'password_request_failed',
          details: { 
            email,
            reason: 'User not found',
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
            code: 'USER_NOT_FOUND',
            message: 'No user found with this email address',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Check if user is active
      if (!user.isActive) {
        await AuditLog.create({
          action: 'password_request_failed',
          userId: user._id,
          details: { 
            email,
            reason: 'User account is inactive',
            endpoint: req.path,
            method: req.method
          },
          ipAddress: req.ip || 'unknown',
          userAgent: req.get('User-Agent') || 'unknown',
          timestamp: new Date(),
          severity: 'warning'
        });

        res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_INACTIVE',
            message: 'User account is inactive',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Create the approval request
      const approvalRequest = await ApprovalRequest.createRequest(user._id, user.email);

      // Log successful request creation
      await AuditLog.create({
        action: 'password_request_created',
        userId: user._id,
        details: { 
          requestId: approvalRequest._id,
          email: user.email,
          expiresAt: approvalRequest.expiresAt,
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(201).json({
        success: true,
        data: {
          requestId: approvalRequest._id,
          status: approvalRequest.status,
          requestedAt: approvalRequest.requestedAt,
          expiresAt: approvalRequest.expiresAt,
          userEmail: approvalRequest.userEmail
        },
        timestamp: new Date().toISOString(),
        requestId
      });

    } catch (error) {
      console.error('Create request error:', error);

      // Log system error
      await AuditLog.create({
        action: 'password_request_error',
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

      if (error instanceof Error && error.message.includes('already has a pending')) {
        res.status(409).json({
          success: false,
          error: {
            code: 'DUPLICATE_REQUEST',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: (req as AuthenticatedRequest).id || 'unknown'
          }
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to create password request',
          timestamp: new Date().toISOString(),
          requestId: (req as AuthenticatedRequest).id || 'unknown'
        }
      });
    }
  }

  /**
   * Get all requests (admin only)
   * GET /api/requests
   */
  static async getAllRequests(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const requestId = req.id || 'unknown';
      const { status, limit = 50, offset = 0 } = req.query;

      // Build filter
      const filter: any = {};
      if (status && typeof status === 'string') {
        if (!['pending', 'approved', 'denied', 'expired'].includes(status)) {
          res.status(400).json({
            success: false,
            error: {
              code: 'INVALID_STATUS',
              message: 'Status must be one of: pending, approved, denied, expired',
              timestamp: new Date().toISOString(),
              requestId
            }
          });
          return;
        }
        filter.status = status;
      }

      // Get requests with pagination
      const requests = await ApprovalRequest.find(filter)
        .populate('userId', 'email isActive')
        .populate('adminResponse.adminId', 'username email')
        .sort({ requestedAt: -1 })
        .limit(Number(limit))
        .skip(Number(offset));

      const totalCount = await ApprovalRequest.countDocuments(filter);

      // Log admin access
      await AuditLog.create({
        action: 'requests_viewed',
        adminId: req.admin?.adminId,
        details: { 
          filter,
          count: requests.length,
          totalCount,
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          requests,
          pagination: {
            total: totalCount,
            limit: Number(limit),
            offset: Number(offset),
            hasMore: Number(offset) + requests.length < totalCount
          }
        },
        timestamp: new Date().toISOString(),
        requestId
      });

    } catch (error) {
      console.error('Get all requests error:', error);

      await AuditLog.create({
        action: 'requests_view_error',
        adminId: req.admin?.adminId,
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
          message: 'Failed to retrieve requests',
          timestamp: new Date().toISOString(),
          requestId: req.id || 'unknown'
        }
      });
    }
  }

  /**
   * Approve a password request
   * PUT /api/requests/:id/approve
   */
  static async approveRequest(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const requestId = req.id || 'unknown';

      // Validate request ID
      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_REQUEST_ID',
            message: 'Invalid request ID format',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Find the approval request
      const approvalRequest = await ApprovalRequest.getRequestById(id);
      if (!approvalRequest) {
        res.status(404).json({
          success: false,
          error: {
            code: 'REQUEST_NOT_FOUND',
            message: 'Approval request not found',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Check if request can be approved
      if (!approvalRequest.canBeApproved()) {
        res.status(400).json({
          success: false,
          error: {
            code: 'CANNOT_APPROVE',
            message: `Request cannot be approved. Current status: ${approvalRequest.status}`,
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Approve the request
      await approvalRequest.approve(new mongoose.Types.ObjectId(req.admin!.adminId), reason);

      // Log approval
      await AuditLog.create({
        action: 'password_request_approved',
        adminId: req.admin?.adminId,
        userId: approvalRequest.userId,
        details: { 
          requestId: approvalRequest._id,
          userEmail: approvalRequest.userEmail,
          reason,
          accessExpiresAt: approvalRequest.accessExpiresAt,
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          requestId: approvalRequest._id,
          status: approvalRequest.status,
          approvedAt: approvalRequest.respondedAt,
          accessExpiresAt: approvalRequest.accessExpiresAt,
          adminResponse: approvalRequest.adminResponse
        },
        timestamp: new Date().toISOString(),
        requestId
      });

    } catch (error) {
      console.error('Approve request error:', error);

      await AuditLog.create({
        action: 'password_request_approve_error',
        adminId: req.admin?.adminId,
        details: { 
          requestId: req.params.id,
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
          message: 'Failed to approve request',
          timestamp: new Date().toISOString(),
          requestId: req.id || 'unknown'
        }
      });
    }
  }

  /**
   * Deny a password request
   * PUT /api/requests/:id/deny
   */
  static async denyRequest(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const requestId = req.id || 'unknown';

      // Validate request ID
      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_REQUEST_ID',
            message: 'Invalid request ID format',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Validate reason (required for denial)
      if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
        res.status(400).json({
          success: false,
          error: {
            code: 'REASON_REQUIRED',
            message: 'Reason is required for denying a request',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Find the approval request
      const approvalRequest = await ApprovalRequest.getRequestById(id);
      if (!approvalRequest) {
        res.status(404).json({
          success: false,
          error: {
            code: 'REQUEST_NOT_FOUND',
            message: 'Approval request not found',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Check if request can be denied
      if (approvalRequest.status !== 'pending') {
        res.status(400).json({
          success: false,
          error: {
            code: 'CANNOT_DENY',
            message: `Request cannot be denied. Current status: ${approvalRequest.status}`,
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Deny the request
      await approvalRequest.deny(new mongoose.Types.ObjectId(req.admin!.adminId), reason.trim());

      // Log denial
      await AuditLog.create({
        action: 'password_request_denied',
        adminId: req.admin?.adminId,
        userId: approvalRequest.userId,
        details: { 
          requestId: approvalRequest._id,
          userEmail: approvalRequest.userEmail,
          reason: reason.trim(),
          endpoint: req.path,
          method: req.method
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          requestId: approvalRequest._id,
          status: approvalRequest.status,
          deniedAt: approvalRequest.respondedAt,
          adminResponse: approvalRequest.adminResponse
        },
        timestamp: new Date().toISOString(),
        requestId
      });

    } catch (error) {
      console.error('Deny request error:', error);

      await AuditLog.create({
        action: 'password_request_deny_error',
        adminId: req.admin?.adminId,
        details: { 
          requestId: req.params.id,
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
          message: 'Failed to deny request',
          timestamp: new Date().toISOString(),
          requestId: req.id || 'unknown'
        }
      });
    }
  }

  /**
   * Get request status (for users to check their request)
   * GET /api/requests/status/:id
   */
  static async getRequestStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const requestId = (req as AuthenticatedRequest).id || 'unknown';

      // Validate request ID
      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_REQUEST_ID',
            message: 'Invalid request ID format',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Find the approval request
      const approvalRequest = await ApprovalRequest.getRequestById(id);
      if (!approvalRequest) {
        res.status(404).json({
          success: false,
          error: {
            code: 'REQUEST_NOT_FOUND',
            message: 'Approval request not found',
            timestamp: new Date().toISOString(),
            requestId
          }
        });
        return;
      }

      // Return status information (without sensitive data)
      const responseData: any = {
        requestId: approvalRequest._id,
        status: approvalRequest.status,
        requestedAt: approvalRequest.requestedAt,
        expiresAt: approvalRequest.expiresAt,
        userEmail: approvalRequest.userEmail
      };

      // Add response details if request has been processed
      if (approvalRequest.adminResponse) {
        responseData.respondedAt = approvalRequest.respondedAt;
        if (approvalRequest.status === 'denied' && approvalRequest.adminResponse.reason) {
          responseData.reason = approvalRequest.adminResponse.reason;
        }
      }

      // Add access information if approved and still valid
      if (approvalRequest.status === 'approved' && approvalRequest.isAccessTokenValid()) {
        responseData.accessExpiresAt = approvalRequest.accessExpiresAt;
        responseData.canAccessPassword = true;
      } else {
        responseData.canAccessPassword = false;
      }

      res.status(200).json({
        success: true,
        data: responseData,
        timestamp: new Date().toISOString(),
        requestId
      });

    } catch (error) {
      console.error('Get request status error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to retrieve request status',
          timestamp: new Date().toISOString(),
          requestId: (req as AuthenticatedRequest).id || 'unknown'
        }
      });
    }
  }
}