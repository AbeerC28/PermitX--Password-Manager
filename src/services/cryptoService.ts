import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import { config } from '../config/environment';

export interface EncryptionResult {
  encryptedData: string;
  iv: string;
}

export interface MaskedPasswordResult {
  maskedPassword: string;
  copyablePassword: string;
}

export interface SecureTokenResult {
  token: string;
  expiresAt: Date;
}

export class CryptoService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32; // 256 bits
  private readonly ivLength = 16; // 128 bits
  private readonly tagLength = 16; // 128 bits
  private readonly encryptionKey: Buffer;

  constructor() {
    // Derive encryption key from environment variable
    this.encryptionKey = this.deriveKey(config.encryptionKey);
  }

  /**
   * Derive a consistent encryption key from the provided key string
   */
  private deriveKey(keyString: string): Buffer {
    return crypto.scryptSync(keyString, 'salt', this.keyLength);
  }

  /**
   * Encrypt password using AES-256-GCM
   */
  async encryptPassword(password: string): Promise<EncryptionResult> {
    try {
      const iv = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipher(this.algorithm, this.encryptionKey);
      cipher.setAAD(Buffer.from('password-encryption'));

      let encrypted = cipher.update(password, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();
      
      // Combine IV, auth tag, and encrypted data
      const combined = Buffer.concat([iv, authTag, Buffer.from(encrypted, 'hex')]);
      
      return {
        encryptedData: combined.toString('base64'),
        iv: iv.toString('hex')
      };
    } catch (error) {
      console.error('Password encryption error:', error);
      throw new Error('Failed to encrypt password');
    }
  }

  /**
   * Decrypt password using AES-256-GCM
   */
  async decryptPassword(encryptedData: string): Promise<string> {
    try {
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract IV, auth tag, and encrypted data
      const iv = combined.subarray(0, this.ivLength);
      const authTag = combined.subarray(this.ivLength, this.ivLength + this.tagLength);
      const encrypted = combined.subarray(this.ivLength + this.tagLength);

      const decipher = crypto.createDecipher(this.algorithm, this.encryptionKey);
      decipher.setAAD(Buffer.from('password-encryption'));
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encrypted, undefined, 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error('Password decryption error:', error);
      throw new Error('Failed to decrypt password');
    }
  }

  /**
   * Hash password using Argon2
   */
  async hashPassword(password: string): Promise<string> {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16, // 64 MB
        timeCost: 3,
        parallelism: 1,
      });
    } catch (error) {
      console.error('Password hashing error:', error);
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify password against hash using Argon2
   */
  async verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean> {
    try {
      return await argon2.verify(hashedPassword, plainPassword);
    } catch (error) {
      console.error('Password verification error:', error);
      return false;
    }
  }

  /**
   * Generate masked password for clipboard copy
   * The actual password is never displayed, only copied to clipboard
   */
  generateMaskedPassword(password: string): MaskedPasswordResult {
    try {
      // Create a masked version that shows only the length and some pattern
      const length = password.length;
      const maskedPassword = '•'.repeat(Math.min(length, 20)) + (length > 20 ? '...' : '');
      
      // The copyable password is the actual password (for clipboard)
      // but it should never be displayed in the UI
      return {
        maskedPassword,
        copyablePassword: password
      };
    } catch (error) {
      console.error('Masked password generation error:', error);
      throw new Error('Failed to generate masked password');
    }
  }

  /**
   * Generate secure session token for password access
   */
  generateSecureSessionToken(expirationMinutes: number = 60): SecureTokenResult {
    try {
      // Generate cryptographically secure random token
      const tokenBytes = crypto.randomBytes(32);
      const timestamp = Date.now().toString(36);
      const randomSuffix = crypto.randomBytes(8).toString('hex');
      
      // Combine timestamp and random data for uniqueness
      const token = `${timestamp}-${tokenBytes.toString('hex')}-${randomSuffix}`;
      
      // Calculate expiration time
      const expiresAt = new Date(Date.now() + (expirationMinutes * 60 * 1000));
      
      return {
        token,
        expiresAt
      };
    } catch (error) {
      console.error('Secure token generation error:', error);
      throw new Error('Failed to generate secure session token');
    }
  }

  /**
   * Generate secure random password
   */
  generateSecurePassword(length: number = 16): string {
    try {
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
      const charsetLength = charset.length;
      let password = '';

      // Ensure we have at least one character from each category
      const categories = [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ', // uppercase
        'abcdefghijklmnopqrstuvwxyz', // lowercase
        '0123456789', // numbers
        '!@#$%^&*()_+-=[]{}|;:,.<>?' // special characters
      ];

      // Add one character from each category
      for (const category of categories) {
        const randomIndex = crypto.randomInt(0, category.length);
        password += category[randomIndex];
      }

      // Fill the rest with random characters from the full charset
      for (let i = password.length; i < length; i++) {
        const randomIndex = crypto.randomInt(0, charsetLength);
        password += charset[randomIndex];
      }

      // Shuffle the password to avoid predictable patterns
      return this.shuffleString(password);
    } catch (error) {
      console.error('Secure password generation error:', error);
      throw new Error('Failed to generate secure password');
    }
  }

  /**
   * Shuffle string characters randomly
   */
  private shuffleString(str: string): string {
    const array = str.split('');
    for (let i = array.length - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
  }

  /**
   * Generate HMAC signature for data integrity
   */
  generateHMAC(data: string, secret?: string): string {
    try {
      const key = secret || config.encryptionKey;
      return crypto.createHmac('sha256', key).update(data).digest('hex');
    } catch (error) {
      console.error('HMAC generation error:', error);
      throw new Error('Failed to generate HMAC');
    }
  }

  /**
   * Verify HMAC signature
   */
  verifyHMAC(data: string, signature: string, secret?: string): boolean {
    try {
      const expectedSignature = this.generateHMAC(data, secret);
      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );
    } catch (error) {
      console.error('HMAC verification error:', error);
      return false;
    }
  }

  /**
   * Generate secure random bytes as hex string
   */
  generateRandomHex(bytes: number = 32): string {
    try {
      return crypto.randomBytes(bytes).toString('hex');
    } catch (error) {
      console.error('Random hex generation error:', error);
      throw new Error('Failed to generate random hex');
    }
  }

  /**
   * Generate secure random bytes as base64 string
   */
  generateRandomBase64(bytes: number = 32): string {
    try {
      return crypto.randomBytes(bytes).toString('base64');
    } catch (error) {
      console.error('Random base64 generation error:', error);
      throw new Error('Failed to generate random base64');
    }
  }

  /**
   * Create a time-based one-time password (TOTP) style token
   * Useful for temporary access tokens
   */
  generateTimeBasedToken(secret?: string, windowMinutes: number = 30): string {
    try {
      const key = secret || config.encryptionKey;
      const timeWindow = Math.floor(Date.now() / (windowMinutes * 60 * 1000));
      const data = `${timeWindow}`;
      
      const hmac = crypto.createHmac('sha256', key);
      hmac.update(data);
      const hash = hmac.digest();
      
      // Extract a 6-digit code from the hash
      const offset = hash[hash.length - 1] & 0x0f;
      const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
      ) % 1000000;
      
      return code.toString().padStart(6, '0');
    } catch (error) {
      console.error('Time-based token generation error:', error);
      throw new Error('Failed to generate time-based token');
    }
  }

  /**
   * Validate time-based token within a time window
   */
  validateTimeBasedToken(token: string, secret?: string, windowMinutes: number = 30, tolerance: number = 1): boolean {
    try {
      // Check current window and adjacent windows for clock drift tolerance
      for (let i = -tolerance; i <= tolerance; i++) {
        const adjustedTime = Date.now() + (i * windowMinutes * 60 * 1000);
        const timeWindow = Math.floor(adjustedTime / (windowMinutes * 60 * 1000));
        
        const key = secret || config.encryptionKey;
        const data = `${timeWindow}`;
        
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        const hash = hmac.digest();
        
        const offset = hash[hash.length - 1] & 0x0f;
        const code = (
          ((hash[offset] & 0x7f) << 24) |
          ((hash[offset + 1] & 0xff) << 16) |
          ((hash[offset + 2] & 0xff) << 8) |
          (hash[offset + 3] & 0xff)
        ) % 1000000;
        
        const expectedToken = code.toString().padStart(6, '0');
        
        if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Time-based token validation error:', error);
      return false;
    }
  }
}

// Export singleton instance
export const cryptoService = new CryptoService();