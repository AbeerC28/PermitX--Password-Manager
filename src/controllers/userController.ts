import { Request, Response } from 'express';
import { User } from '../models/User';
import { AuditLog } from '../models/AuditLog';
import { AuthenticatedRequest } from '../middleware/authMiddleware';

export class UserController {
  /**
   * Create a new user
   * POST /api/users
   */
  static async createUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      // Validate required fields
      if (!email || !password) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Email and password are required',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
        return;
      }

      // Create user using model static method
      const user = await User.createUser({ email, password });

      // Log user creation
      await AuditLog.create({
        action: 'user_created',
        adminId: req.admin?.adminId,
        details: { 
          userEmail: email,
          userId: user._id.toString()
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: user._id,
            email: user.email,
            isActive: user.isActive,
            createdAt: user.createdAt,
            lastPasswordUpdate: user.lastPasswordUpdate
          }
        },
        message: 'User created successfully'
      });

    } catch (error) {
      console.error('Create user error:', error);

      // Log error
      await AuditLog.create({
        action: 'user_creation_failed',
        adminId: req.admin?.adminId,
        details: { 
          error: error instanceof Error ? error.message : 'Unknown error',
          userEmail: req.body.email
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'error'
      });

      if (error instanceof Error && error.message.includes('already exists')) {
        res.status(409).json({
          success: false,
          error: {
            code: 'USER_EXISTS',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      } else if (error instanceof Error && error.message.includes('Validation error')) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      } else {
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to create user',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      }
    }
  }

  /**
   * Get all users
   * GET /api/users
   */
  static async getAllUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const includeInactive = req.query.includeInactive === 'true';
      
      const users = await User.getAllUsers(includeInactive);

      // Log user list access
      await AuditLog.create({
        action: 'users_listed',
        adminId: req.admin?.adminId,
        details: { 
          userCount: users.length,
          includeInactive
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          users: users.map(user => ({
            id: user._id,
            email: user.email,
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
            lastPasswordUpdate: user.lastPasswordUpdate
          })),
          count: users.length
        }
      });

    } catch (error) {
      console.error('Get users error:', error);

      // Log error
      await AuditLog.create({
        action: 'users_list_failed',
        adminId: req.admin?.adminId,
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
          code: 'INTERNAL_ERROR',
          message: 'Failed to retrieve users',
          timestamp: new Date().toISOString(),
          requestId: req.id || 'unknown'
        }
      });
    }
  }

  /**
   * Update user password
   * PUT /api/users/:id
   */
  static async updateUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData = req.body;

      // Validate user ID
      if (!id || !id.match(/^[0-9a-fA-F]{24}$/)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_USER_ID',
            message: 'Invalid user ID format',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
        return;
      }

      // Update user using model static method
      const updatedUser = await User.updateUser(id, updateData);

      // Log user update
      await AuditLog.create({
        action: 'user_updated',
        adminId: req.admin?.adminId,
        details: { 
          userId: id,
          userEmail: updatedUser.email,
          updatedFields: Object.keys(updateData)
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          user: {
            id: updatedUser._id,
            email: updatedUser.email,
            isActive: updatedUser.isActive,
            createdAt: updatedUser.createdAt,
            updatedAt: updatedUser.updatedAt,
            lastPasswordUpdate: updatedUser.lastPasswordUpdate
          }
        },
        message: 'User updated successfully'
      });

    } catch (error) {
      console.error('Update user error:', error);

      // Log error
      await AuditLog.create({
        action: 'user_update_failed',
        adminId: req.admin?.adminId,
        details: { 
          userId: req.params.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'error'
      });

      if (error instanceof Error && error.message.includes('not found')) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      } else if (error instanceof Error && error.message.includes('Validation error')) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      } else {
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to update user',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      }
    }
  }

  /**
   * Delete user
   * DELETE /api/users/:id
   */
  static async deleteUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Validate user ID
      if (!id || !id.match(/^[0-9a-fA-F]{24}$/)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_USER_ID',
            message: 'Invalid user ID format',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
        return;
      }

      // Delete user using model static method
      const deletedUser = await User.deleteUser(id);

      if (!deletedUser) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
        return;
      }

      // Log user deletion
      await AuditLog.create({
        action: 'user_deleted',
        adminId: req.admin?.adminId,
        details: { 
          userId: id,
          userEmail: deletedUser.email
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'info'
      });

      res.status(200).json({
        success: true,
        data: {
          deletedUser: {
            id: deletedUser._id,
            email: deletedUser.email
          }
        },
        message: 'User deleted successfully'
      });

    } catch (error) {
      console.error('Delete user error:', error);

      // Log error
      await AuditLog.create({
        action: 'user_deletion_failed',
        adminId: req.admin?.adminId,
        details: { 
          userId: req.params.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date(),
        severity: 'error'
      });

      if (error instanceof Error && error.message.includes('not found')) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: error.message,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      } else {
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to delete user',
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
          }
        });
      }
    }
  }
}