import { Server as SocketIOServer, Socket } from 'socket.io';
import { authService, TokenPayload, SessionData } from './authService';
import { AuditLog } from '../models/AuditLog';

export interface AuthenticatedSocket extends Socket {
  admin?: {
    adminId: string;
    username: string;
    email: string;
    sessionId: string;
  };
  user?: {
    userId: string;
    email: string;
  };
}

export interface SocketAuthData {
  token?: string;
  userEmail?: string; // For user connections
}

export class SocketService {
  private io: SocketIOServer;
  private connectedAdmins = new Map<string, string>(); // adminId -> socketId
  private connectedUsers = new Map<string, string>(); // userEmail -> socketId

  constructor(io: SocketIOServer) {
    this.io = io;
    this.initializeSocketHandlers();
  }

  private initializeSocketHandlers(): void {
    // Authentication middleware for Socket.io
    this.io.use(async (socket: AuthenticatedSocket, next) => {
      try {
        const authData = socket.handshake.auth as SocketAuthData;
        const { token, userEmail } = authData;

        // Admin authentication via JWT token
        if (token) {
          const validation = await authService.validateToken(token);
          
          if (!validation.valid || !validation.payload || !validation.session) {
            // Log failed authentication
            await AuditLog.create({
              action: 'socket_auth_failed',
              details: { 
                reason: 'Invalid or expired token',
                socketId: socket.id,
                type: 'admin'
              },
              ipAddress: socket.handshake.address || 'unknown',
              userAgent: socket.handshake.headers['user-agent'] || 'unknown',
              timestamp: new Date(),
              severity: 'warning'
            });

            return next(new Error('Authentication failed'));
          }

          // Attach admin data to socket
          socket.admin = {
            adminId: validation.payload.adminId,
            username: validation.payload.username,
            email: validation.payload.email,
            sessionId: validation.payload.sessionId
          };

          // Log successful admin connection
          await AuditLog.create({
            action: 'socket_admin_connected',
            adminId: validation.payload.adminId,
            details: { 
              username: validation.payload.username,
              socketId: socket.id
            },
            ipAddress: socket.handshake.address || 'unknown',
            userAgent: socket.handshake.headers['user-agent'] || 'unknown',
            timestamp: new Date(),
            severity: 'info'
          });

        } 
        // User authentication via email (for status updates)
        else if (userEmail) {
          // Basic validation for user email format
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(userEmail)) {
            return next(new Error('Invalid email format'));
          }

          socket.user = {
            userId: userEmail, // Using email as user identifier for now
            email: userEmail
          };

          // Log user connection
          await AuditLog.create({
            action: 'socket_user_connected',
            details: { 
              userEmail,
              socketId: socket.id
            },
            ipAddress: socket.handshake.address || 'unknown',
            userAgent: socket.handshake.headers['user-agent'] || 'unknown',
            timestamp: new Date(),
            severity: 'info'
          });
        } 
        else {
          return next(new Error('Authentication required'));
        }

        next();
      } catch (error) {
        console.error('Socket authentication error:', error);
        
        await AuditLog.create({
          action: 'socket_auth_error',
          details: { 
            error: error instanceof Error ? error.message : 'Unknown error',
            socketId: socket.id
          },
          ipAddress: socket.handshake.address || 'unknown',
          userAgent: socket.handshake.headers['user-agent'] || 'unknown',
          timestamp: new Date(),
          severity: 'error'
        });

        next(new Error('Authentication system error'));
      }
    });

    // Connection handler
    this.io.on('connection', (socket: AuthenticatedSocket) => {
      this.handleConnection(socket);
    });
  }

  private handleConnection(socket: AuthenticatedSocket): void {
    console.log(`Socket connected: ${socket.id}`);

    // Handle admin connections
    if (socket.admin) {
      this.handleAdminConnection(socket);
    }

    // Handle user connections
    if (socket.user) {
      this.handleUserConnection(socket);
    }

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      this.handleDisconnection(socket, reason);
    });

    // Handle connection errors
    socket.on('error', (error) => {
      this.handleConnectionError(socket, error);
    });

    // Heartbeat/ping handling for connection health
    socket.on('ping', () => {
      socket.emit('pong');
    });
  }

  private handleAdminConnection(socket: AuthenticatedSocket): void {
    if (!socket.admin) return;

    const { adminId, username } = socket.admin;

    // Store admin connection
    this.connectedAdmins.set(adminId, socket.id);

    // Join admin room for notifications
    socket.join('admin-notifications');
    
    // Join personal admin room
    socket.join(`admin-${adminId}`);

    console.log(`Admin ${username} (${adminId}) connected with socket ${socket.id}`);

    // Handle admin-specific events
    socket.on('join-admin-room', () => {
      socket.join('admin-notifications');
      socket.emit('joined-room', { room: 'admin-notifications' });
    });

    // Handle admin status request
    socket.on('get-admin-status', () => {
      socket.emit('admin-status', {
        connected: true,
        adminId,
        username,
        connectedAt: new Date().toISOString()
      });
    });

    // Handle request for pending requests count
    socket.on('get-pending-requests', async () => {
      try {
        const { ApprovalRequest } = await import('../models/ApprovalRequest');
        const pendingCount = await ApprovalRequest.countDocuments({ status: 'pending' });
        socket.emit('pending-requests-count', { count: pendingCount });
      } catch (error) {
        console.error('Error getting pending requests count:', error);
        socket.emit('error', { message: 'Failed to get pending requests count' });
      }
    });

    // Handle manual request expiration
    socket.on('expire-request', async (data: { requestId: string }) => {
      try {
        const { expirationService } = await import('./expirationService');
        const success = await expirationService.expireRequestById(data.requestId, adminId);
        
        if (success) {
          socket.emit('request-expired-manually', { 
            requestId: data.requestId,
            success: true 
          });
          
          // Notify all admins about manual expiration
          this.notifyAdmins('request-manually-expired', {
            requestId: data.requestId,
            expiredBy: username,
            expiredAt: new Date()
          });
        } else {
          socket.emit('request-expired-manually', { 
            requestId: data.requestId,
            success: false,
            error: 'Request not found or cannot be expired'
          });
        }
      } catch (error) {
        console.error('Error manually expiring request:', error);
        socket.emit('error', { message: 'Failed to expire request' });
      }
    });

    // Handle admin activity ping
    socket.on('admin-activity', () => {
      // Update admin activity in notification scheduler
      import('./notificationSchedulerService').then(({ notificationScheduler }) => {
        notificationScheduler.updateAdminActivity();
      });
    });

    // Notify admin of successful connection
    socket.emit('admin-connected', {
      adminId,
      username,
      connectedAt: new Date().toISOString()
    });
  }

  private handleUserConnection(socket: AuthenticatedSocket): void {
    if (!socket.user) return;

    const { userId, email } = socket.user;

    // Store user connection
    this.connectedUsers.set(email, socket.id);

    // Join user-specific room for status updates
    socket.join(`user-${email}`);

    console.log(`User ${email} connected with socket ${socket.id}`);

    // Handle user-specific events
    socket.on('join-user-room', (data: { email: string }) => {
      if (data.email === email) {
        socket.join(`user-${email}`);
        socket.emit('joined-room', { room: `user-${email}` });
      }
    });

    // Handle user status request
    socket.on('get-user-status', () => {
      socket.emit('user-status', {
        connected: true,
        email,
        connectedAt: new Date().toISOString()
      });
    });

    // Handle request status check
    socket.on('check-request-status', async (data: { requestId: string }) => {
      try {
        const { ApprovalRequest } = await import('../models/ApprovalRequest');
        const request = await ApprovalRequest.getRequestById(data.requestId);
        
        if (request && request.userEmail === email) {
          socket.emit('request-status-update', {
            requestId: request._id,
            status: request.status,
            requestedAt: request.requestedAt,
            respondedAt: request.respondedAt,
            expiresAt: request.expiresAt,
            canAccessPassword: request.isAccessTokenValid()
          });
        } else {
          socket.emit('error', { message: 'Request not found or access denied' });
        }
      } catch (error) {
        console.error('Error checking request status:', error);
        socket.emit('error', { message: 'Failed to check request status' });
      }
    });

    // Handle user activity ping
    socket.on('user-activity', () => {
      // Log user activity if needed
      console.log(`User activity from ${email}`);
    });

    // Notify user of successful connection
    socket.emit('user-connected', {
      email,
      connectedAt: new Date().toISOString()
    });
  }

  private async handleDisconnection(socket: AuthenticatedSocket, reason: string): Promise<void> {
    console.log(`Socket disconnected: ${socket.id}, reason: ${reason}`);

    try {
      // Handle admin disconnection
      if (socket.admin) {
        const { adminId, username } = socket.admin;
        this.connectedAdmins.delete(adminId);

        // Log admin disconnection
        await AuditLog.create({
          action: 'socket_admin_disconnected',
          adminId,
          details: { 
            username,
            socketId: socket.id,
            reason
          },
          ipAddress: socket.handshake.address || 'unknown',
          userAgent: socket.handshake.headers['user-agent'] || 'unknown',
          timestamp: new Date(),
          severity: 'info'
        });

        console.log(`Admin ${username} (${adminId}) disconnected`);
      }

      // Handle user disconnection
      if (socket.user) {
        const { email } = socket.user;
        this.connectedUsers.delete(email);

        // Log user disconnection
        await AuditLog.create({
          action: 'socket_user_disconnected',
          details: { 
            userEmail: email,
            socketId: socket.id,
            reason
          },
          ipAddress: socket.handshake.address || 'unknown',
          userAgent: socket.handshake.headers['user-agent'] || 'unknown',
          timestamp: new Date(),
          severity: 'info'
        });

        console.log(`User ${email} disconnected`);
      }
    } catch (error) {
      console.error('Error handling disconnection:', error);
    }
  }

  private async handleConnectionError(socket: AuthenticatedSocket, error: Error): Promise<void> {
    console.error(`Socket error for ${socket.id}:`, error);

    try {
      await AuditLog.create({
        action: 'socket_connection_error',
        adminId: socket.admin?.adminId,
        details: { 
          socketId: socket.id,
          error: error.message,
          adminId: socket.admin?.adminId,
          userEmail: socket.user?.email
        },
        ipAddress: socket.handshake.address || 'unknown',
        userAgent: socket.handshake.headers['user-agent'] || 'unknown',
        timestamp: new Date(),
        severity: 'error'
      });
    } catch (logError) {
      console.error('Error logging socket error:', logError);
    }
  }

  // Public methods for sending notifications

  /**
   * Send notification to all connected admins
   */
  public notifyAdmins(event: string, data: any): void {
    this.io.to('admin-notifications').emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send notification to specific admin
   */
  public notifyAdmin(adminId: string, event: string, data: any): void {
    this.io.to(`admin-${adminId}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send status update to specific user
   */
  public notifyUser(userEmail: string, event: string, data: any): void {
    this.io.to(`user-${userEmail}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send broadcast message to all connected clients
   */
  public broadcast(event: string, data: any): void {
    this.io.emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Check if admin is connected
   */
  public isAdminConnected(adminId: string): boolean {
    return this.connectedAdmins.has(adminId);
  }

  /**
   * Check if user is connected
   */
  public isUserConnected(userEmail: string): boolean {
    return this.connectedUsers.has(userEmail);
  }

  /**
   * Get connected admin count
   */
  public getConnectedAdminCount(): number {
    return this.connectedAdmins.size;
  }

  /**
   * Get connected user count
   */
  public getConnectedUserCount(): number {
    return this.connectedUsers.size;
  }

  /**
   * Get connection statistics
   */
  public getConnectionStats(): {
    admins: number;
    users: number;
    total: number;
  } {
    return {
      admins: this.connectedAdmins.size,
      users: this.connectedUsers.size,
      total: this.connectedAdmins.size + this.connectedUsers.size
    };
  }

  /**
   * Force disconnect a socket by admin ID
   */
  public disconnectAdmin(adminId: string, reason: string = 'Forced disconnect'): boolean {
    const socketId = this.connectedAdmins.get(adminId);
    if (socketId) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) {
        socket.disconnect(true);
        this.connectedAdmins.delete(adminId);
        console.log(`Forcefully disconnected admin ${adminId}`);
        return true;
      }
    }
    return false;
  }

  /**
   * Force disconnect a socket by user email
   */
  public disconnectUser(userEmail: string, reason: string = 'Forced disconnect'): boolean {
    const socketId = this.connectedUsers.get(userEmail);
    if (socketId) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) {
        socket.disconnect(true);
        this.connectedUsers.delete(userEmail);
        console.log(`Forcefully disconnected user ${userEmail}`);
        return true;
      }
    }
    return false;
  }
}

// Export singleton instance (will be initialized in server.ts)
let socketService: SocketService;

export const initializeSocketService = (io: SocketIOServer): SocketService => {
  socketService = new SocketService(io);
  return socketService;
};

export const getSocketService = (): SocketService => {
  if (!socketService) {
    throw new Error('SocketService not initialized. Call initializeSocketService first.');
  }
  return socketService;
};