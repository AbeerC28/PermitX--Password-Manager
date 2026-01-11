/**
 * Service for handling secure clipboard operations with API integration
 */

import { copyPasswordToClipboard, ClipboardResult, getClipboardCapabilities } from '../utils/clipboard';

export interface PasswordAccessRequest {
  requestId: string;
  sessionToken?: string;
}

export interface PasswordAccessResponse {
  maskedPassword: string;
  sessionExpiresAt: Date;
  clearAfter?: number;
}

export interface ClipboardServiceOptions {
  apiBaseUrl?: string;
  defaultClearTime?: number;
}

export class ClipboardService {
  private apiBaseUrl: string;
  private defaultClearTime: number;

  constructor(options: ClipboardServiceOptions = {}) {
    this.apiBaseUrl = options.apiBaseUrl || '/api';
    this.defaultClearTime = options.defaultClearTime || 60000; // 60 seconds
  }

  /**
   * Fetches the masked password from the API and copies it to clipboard
   */
  async copyPasswordFromAPI(
    requestId: string,
    sessionToken?: string
  ): Promise<ClipboardResult & { sessionExpiresAt?: Date }> {
    try {
      // Fetch the masked password from the API
      const response = await fetch(`${this.apiBaseUrl}/password/access`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken && { 'Authorization': `Bearer ${sessionToken}` })
        },
        body: JSON.stringify({ requestId })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data: PasswordAccessResponse = await response.json();

      // Copy the masked password to clipboard
      const clipboardResult = await copyPasswordToClipboard(
        data.maskedPassword,
        { clearAfter: data.clearAfter || this.defaultClearTime }
      );

      return {
        ...clipboardResult,
        sessionExpiresAt: data.sessionExpiresAt
      };

    } catch (error) {
      console.error('Failed to copy password from API:', error);
      
      return {
        success: false,
        message: error instanceof Error 
          ? error.message 
          : 'Failed to access password. Please try again.'
      };
    }
  }

  /**
   * Triggers clipboard copy operation via API endpoint
   * This method is used when the backend handles the clipboard operation
   */
  async triggerClipboardCopy(
    requestId: string,
    sessionToken?: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${this.apiBaseUrl}/password/copy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken && { 'Authorization': `Bearer ${sessionToken}` })
        },
        body: JSON.stringify({ requestId })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      return {
        success: true,
        message: data.message || 'Password copied to clipboard successfully'
      };

    } catch (error) {
      console.error('Failed to trigger clipboard copy:', error);
      
      return {
        success: false,
        message: error instanceof Error 
          ? error.message 
          : 'Failed to copy password. Please try again.'
      };
    }
  }

  /**
   * Validates if a session is still valid for password access
   */
  async validateSession(
    requestId: string,
    sessionToken: string
  ): Promise<{ valid: boolean; expiresAt?: Date; message?: string }> {
    try {
      const response = await fetch(`${this.apiBaseUrl}/password/validate-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({ requestId })
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          valid: false,
          message: data.message || 'Session validation failed'
        };
      }

      return {
        valid: data.valid,
        expiresAt: data.expiresAt ? new Date(data.expiresAt) : undefined,
        message: data.message
      };

    } catch (error) {
      console.error('Failed to validate session:', error);
      
      return {
        valid: false,
        message: 'Failed to validate session. Please try again.'
      };
    }
  }

  /**
   * Gets the browser's clipboard capabilities
   */
  getClipboardCapabilities(): {
    supported: boolean;
    method: 'modern' | 'legacy' | 'none';
    features: string[];
    secureContext: boolean;
    userAgent: string;
  } {
    return getClipboardCapabilities();
  }
}

// Default instance
export const clipboardService = new ClipboardService();