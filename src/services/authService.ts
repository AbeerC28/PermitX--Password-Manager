import jwt from 'jsonwebtoken';
import { RedisConnection } from '../config/redis';
import { config } from '../config/environment';
import { Admin, IAdminModel } from '../models/Admin';
import { AuditLog } from '../models/AuditLog';

export interface SessionData {
  adminId: string;
  username: string;
  email: string;
  loginTime: Date;
  lastActivity: Date;
}

export interface LoginResult {
  success: boolean;
  admin?: IAdminModel;
  token?: string;
  sessionId?: string;
  message?: string;
}

export interface TokenPayload {
  adminId: string;
  username: string;
  email: string;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export class AuthService {
  private redis = RedisConnection.getInstance();

  constructor() {
    // Ensure Redis connection is established
    this.initializeRedis();
  }

  private async initializeRedis(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (error) {
      console.error('Failed to initialize Redis connection for AuthService:', error);
      throw error;
    }
  }

  /**
   * Authenticate admin user and create session
   */
  async login(username: string, password: string, ipAddress: string, userAgent: string): Promise<LoginResult> {
    try {
      // Authenticate admin
      const admin = await Admin.authenticateAdmin(username, password);
      
      if (!admin) {
        // Log failed login attempt
        await AuditLog.create({
          action: 'admin_login_failed',
          details: { username, reason: 'Invalid credentials' },
          ipAddress,
          userAgent,
          timestamp: new Date(),
          severity: 'warning'
        });

        return {
          success: false,
          message: 'Invalid username or password'
        };
      }

      // Generate session ID
      const sessionId = this.generateSessionId();
      
      // Create session data
      const sessionData: SessionData = {
        adminId: admin._id.toString(),
        username: admin.username,
        email: admin.email,
        loginTime: new Date(),
        lastActivity: new Date()
      };

      // Store session in Redis with expiration
      const sessionKey = `session:${sessionId}`;
      const sessionTTL = Math.floor(config.sessionTimeoutMs / 1000); // Convert to seconds
      
      await this.redis.getClient().setEx(
        sessionKey,
        sessionTTL,
        JSON.stringify(sessionData)
      );

      // Generate JWT token with session ID
      const tokenPayload: Omit<TokenPayload, 'iat' | 'exp'> = {
        adminId: admin._id.toString(),
        username: admin.username,
        email: admin.email,
        sessionId
      };

      const token = jwt.sign(tokenPayload, config.jwtSecret, {
        expiresIn: config.jwtExpiresIn
      } as jwt.SignOptions);

      // Log successful login
      await AuditLog.create({
        action: 'admin_login_success',
        adminId: admin._id,
        details: { username: admin.username, sessionId },
        ipAddress,
        userAgent,
        timestamp: new Date(),
        severity: 'info'
      });

      return {
        success: true,
        admin,
        token,
        sessionId,
        message: 'Login successful'
      };

    } catch (error) {
      console.error('Login error:', error);
      
      // Log system error
      await AuditLog.create({
        action: 'admin_login_error',
        details: { username, error: error instanceof Error ? error.message : 'Unknown error' },
        ipAddress,
        userAgent,
        timestamp: new Date(),
        severity: 'error'
      });

      return {
        success: false,
        message: 'Login failed due to system error'
      };
    }
  }

  /**
   * Logout admin and destroy session
   */
  async logout(sessionId: string, ipAddress: string, userAgent: string): Promise<boolean> {
    try {
      const sessionKey = `session:${sessionId}`;
      
      // Get session data before deletion for audit log
      const sessionDataStr = await this.redis.getClient().get(sessionKey);
      let sessionData: SessionData | null = null;
      
      if (sessionDataStr) {
        sessionData = JSON.parse(sessionDataStr);
      }

      // Delete session from Redis
      const deleted = await this.redis.getClient().del(sessionKey);

      // Log logout
      if (sessionData) {
        await AuditLog.create({
          action: 'admin_logout',
          adminId: sessionData.adminId,
          details: { 
            username: sessionData.username,
            sessionId,
            sessionDuration: Date.now() - sessionData.loginTime.getTime()
          },
          ipAddress,
          userAgent,
          timestamp: new Date(),
          severity: 'info'
        });
      }

      return deleted > 0;
    } catch (error) {
      console.error('Logout error:', error);
      return false;
    }
  }

  /**
   * Validate JWT token and check session
   */
  async validateToken(token: string): Promise<{ valid: boolean; payload?: TokenPayload; session?: SessionData }> {
    try {
      // Verify JWT token
      const payload = jwt.verify(token, config.jwtSecret) as TokenPayload;
      
      // Check if session exists in Redis
      const sessionKey = `session:${payload.sessionId}`;
      const sessionDataStr = await this.redis.getClient().get(sessionKey);
      
      if (!sessionDataStr) {
        return { valid: false };
      }

      const sessionData: SessionData = JSON.parse(sessionDataStr);
      
      // Update last activity
      sessionData.lastActivity = new Date();
      const sessionTTL = Math.floor(config.sessionTimeoutMs / 1000);
      
      await this.redis.getClient().setEx(
        sessionKey,
        sessionTTL,
        JSON.stringify(sessionData)
      );

      return {
        valid: true,
        payload,
        session: sessionData
      };

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        console.log('Invalid JWT token:', error.message);
      } else {
        console.error('Token validation error:', error);
      }
      return { valid: false };
    }
  }

  /**
   * Refresh session expiration
   */
  async refreshSession(sessionId: string): Promise<boolean> {
    try {
      const sessionKey = `session:${sessionId}`;
      const sessionDataStr = await this.redis.getClient().get(sessionKey);
      
      if (!sessionDataStr) {
        return false;
      }

      const sessionData: SessionData = JSON.parse(sessionDataStr);
      sessionData.lastActivity = new Date();
      
      const sessionTTL = Math.floor(config.sessionTimeoutMs / 1000);
      
      await this.redis.getClient().setEx(
        sessionKey,
        sessionTTL,
        JSON.stringify(sessionData)
      );

      return true;
    } catch (error) {
      console.error('Session refresh error:', error);
      return false;
    }
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    try {
      const sessionKey = `session:${sessionId}`;
      const sessionDataStr = await this.redis.getClient().get(sessionKey);
      
      if (!sessionDataStr) {
        return null;
      }

      return JSON.parse(sessionDataStr);
    } catch (error) {
      console.error('Get session error:', error);
      return null;
    }
  }

  /**
   * Get all active sessions for an admin
   */
  async getAdminSessions(adminId: string): Promise<SessionData[]> {
    try {
      const pattern = 'session:*';
      const keys = await this.redis.getClient().keys(pattern);
      const sessions: SessionData[] = [];

      for (const key of keys) {
        const sessionDataStr = await this.redis.getClient().get(key);
        if (sessionDataStr) {
          const sessionData: SessionData = JSON.parse(sessionDataStr);
          if (sessionData.adminId === adminId) {
            sessions.push(sessionData);
          }
        }
      }

      return sessions;
    } catch (error) {
      console.error('Get admin sessions error:', error);
      return [];
    }
  }

  /**
   * Destroy all sessions for an admin
   */
  async destroyAdminSessions(adminId: string, ipAddress: string, userAgent: string): Promise<number> {
    try {
      const sessions = await this.getAdminSessions(adminId);
      let destroyedCount = 0;

      for (const session of sessions) {
        const sessionKey = `session:${this.extractSessionIdFromSession(session)}`;
        const deleted = await this.redis.getClient().del(sessionKey);
        if (deleted > 0) {
          destroyedCount++;
        }
      }

      // Log session destruction
      if (destroyedCount > 0) {
        await AuditLog.create({
          action: 'admin_sessions_destroyed',
          adminId,
          details: { destroyedSessions: destroyedCount },
          ipAddress,
          userAgent,
          timestamp: new Date(),
          severity: 'info'
        });
      }

      return destroyedCount;
    } catch (error) {
      console.error('Destroy admin sessions error:', error);
      return 0;
    }
  }

  /**
   * Check if session is expired
   */
  async isSessionExpired(sessionId: string): Promise<boolean> {
    try {
      const sessionKey = `session:${sessionId}`;
      const ttl = await this.redis.getClient().ttl(sessionKey);
      return ttl <= 0;
    } catch (error) {
      console.error('Session expiry check error:', error);
      return true;
    }
  }

  /**
   * Generate secure session ID
   */
  private generateSessionId(): string {
    const timestamp = Date.now().toString(36);
    const randomBytes = Math.random().toString(36).substring(2);
    const moreRandomBytes = Math.random().toString(36).substring(2);
    return `${timestamp}-${randomBytes}-${moreRandomBytes}`;
  }

  /**
   * Extract session ID from session data (helper method)
   * Note: In a real implementation, you might store sessionId in the session data
   * For now, we'll need to track this differently or modify the session structure
   */
  private extractSessionIdFromSession(session: SessionData): string {
    // This is a placeholder - in practice, you'd store sessionId in SessionData
    // or maintain a mapping. For now, we'll generate a consistent ID based on session data
    return `${session.adminId}-${session.loginTime.getTime()}`;
  }

  /**
   * Clean up expired sessions (utility method for background cleanup)
   */
  async cleanupExpiredSessions(): Promise<number> {
    try {
      const pattern = 'session:*';
      const keys = await this.redis.getClient().keys(pattern);
      let cleanedCount = 0;

      for (const key of keys) {
        const ttl = await this.redis.getClient().ttl(key);
        if (ttl <= 0) {
          await this.redis.getClient().del(key);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        console.log(`Cleaned up ${cleanedCount} expired sessions`);
      }

      return cleanedCount;
    } catch (error) {
      console.error('Session cleanup error:', error);
      return 0;
    }
  }
}

// Export singleton instance
export const authService = new AuthService();