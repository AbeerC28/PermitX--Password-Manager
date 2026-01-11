import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

interface Config {
  // Server Configuration
  port: number;
  nodeEnv: string;

  // Database Configuration
  mongodbUri: string;
  mongodbTestUri: string;

  // Redis Configuration
  redisHost: string;
  redisPort: number;
  redisPassword?: string;

  // JWT Configuration
  jwtSecret: string;
  jwtExpiresIn: string;
  accessTokenExpiresIn: string;

  // Encryption Configuration
  encryptionKey: string;

  // SendGrid Configuration
  sendgridApiKey: string;
  fromEmail: string;

  // Twilio Configuration
  twilioAccountSid: string;
  twilioAuthToken: string;
  twilioPhoneNumber: string;

  // Security Configuration
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  sessionTimeoutMs: number;

  // Audit Configuration
  auditRetentionDays: number;
  auditRetentionEnabled: boolean;
  auditCleanupSchedule: string;

  // CORS Configuration
  corsOrigin: string;
}

const requiredEnvVars = ['JWT_SECRET', 'ENCRYPTION_KEY', 'MONGODB_URI'];

// Validate required environment variables
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

export const config: Config = {
  // Server Configuration
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  // Database Configuration
  mongodbUri: process.env.MONGODB_URI!,
  mongodbTestUri:
    process.env.MONGODB_TEST_URI ||
    'mongodb://localhost:27017/auth-password-manager-test',

  // Redis Configuration
  redisHost: process.env.REDIS_HOST || 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT || '6379', 10),
  redisPassword: process.env.REDIS_PASSWORD,

  // JWT Configuration
  jwtSecret: process.env.JWT_SECRET!,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
  accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '1h',

  // Encryption Configuration
  encryptionKey: process.env.ENCRYPTION_KEY!,

  // SendGrid Configuration
  sendgridApiKey: process.env.SENDGRID_API_KEY || '',
  fromEmail: process.env.FROM_EMAIL || 'noreply@yourcompany.com',

  // Twilio Configuration
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID || '',
  twilioAuthToken: process.env.TWILIO_AUTH_TOKEN || '',
  twilioPhoneNumber: process.env.TWILIO_PHONE_NUMBER || '',

  // Security Configuration
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  rateLimitMaxRequests: parseInt(
    process.env.RATE_LIMIT_MAX_REQUESTS || '100',
    10
  ),
  sessionTimeoutMs: parseInt(process.env.SESSION_TIMEOUT_MS || '3600000', 10), // 1 hour

  // Audit Configuration
  auditRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10),
  auditRetentionEnabled: process.env.AUDIT_RETENTION_ENABLED !== 'false',
  auditCleanupSchedule: process.env.AUDIT_CLEANUP_SCHEDULE || '0 2 * * 0', // Weekly at 2 AM on Sunday

  // CORS Configuration
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
};

export default config;
