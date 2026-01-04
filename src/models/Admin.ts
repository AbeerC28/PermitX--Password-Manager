import mongoose, { Document, Schema } from 'mongoose';
import * as argon2 from 'argon2';
import Joi from 'joi';
import jwt from 'jsonwebtoken';
import { config } from '../config/environment';

// Admin interface based on design document
export interface IAdmin extends Document {
  _id: mongoose.Types.ObjectId;
  username: string;
  encryptedPassword: string;
  email: string;
  notificationPreferences: {
    email: boolean;
    sms: boolean;
    phoneNumber?: string;
  };
  createdAt: Date;
  lastLogin: Date;
}

// Admin methods interface
export interface IAdminMethods {
  verifyPassword(password: string): Promise<boolean>;
  updatePassword(newPassword: string): Promise<void>;
  generateAuthToken(): string;
  updateNotificationPreferences(preferences: Partial<IAdmin['notificationPreferences']>): Promise<void>;
  recordLogin(): Promise<void>;
}

// Admin model interface combining document and methods
export interface IAdminModel extends IAdmin, IAdminMethods {}

// Static methods interface
export interface IAdminStatics {
  createAdmin(adminData: { 
    username: string; 
    password: string; 
    email: string;
    notificationPreferences?: Partial<IAdmin['notificationPreferences']>;
  }): Promise<IAdminModel>;
  authenticateAdmin(username: string, password: string): Promise<IAdminModel | null>;
  getAdminById(adminId: string): Promise<IAdminModel | null>;
  updateAdmin(adminId: string, updateData: any): Promise<IAdminModel>;
}

// Combined model interface
export interface IAdminModelStatic extends mongoose.Model<IAdminModel>, IAdminStatics {}

// Mongoose schema definition
const adminSchema = new Schema<IAdminModel>(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters long'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
      validate: {
        validator: function(username: string) {
          // Allow alphanumeric characters, underscores, and hyphens
          const usernameRegex = /^[a-zA-Z0-9_-]+$/;
          return usernameRegex.test(username);
        },
        message: 'Username can only contain letters, numbers, underscores, and hyphens'
      }
    },
    encryptedPassword: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters long']
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: function(email: string) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          return emailRegex.test(email);
        },
        message: 'Please provide a valid email address'
      }
    },
    notificationPreferences: {
      email: {
        type: Boolean,
        default: true
      },
      sms: {
        type: Boolean,
        default: false
      },
      phoneNumber: {
        type: String,
        required: function(this: IAdmin) {
          return this.notificationPreferences.sms;
        },
        validate: {
          validator: function(phoneNumber: string) {
            if (!phoneNumber) return true; // Optional if SMS is disabled
            // Basic phone number validation (international format)
            const phoneRegex = /^\+[1-9]\d{1,14}$/;
            return phoneRegex.test(phoneNumber);
          },
          message: 'Please provide a valid phone number in international format (+1234567890)'
        }
      }
    },
    lastLogin: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt
    toJSON: {
      transform: function(doc, ret) {
        // Remove sensitive data from JSON output
        delete ret.encryptedPassword;
        return ret;
      }
    }
  }
);

// Instance methods
adminSchema.methods.verifyPassword = async function(password: string): Promise<boolean> {
  try {
    return await argon2.verify(this.encryptedPassword, password);
  } catch (error) {
    throw new Error('Password verification failed');
  }
};

adminSchema.methods.updatePassword = async function(newPassword: string): Promise<void> {
  try {
    this.encryptedPassword = await argon2.hash(newPassword);
    await this.save();
  } catch (error) {
    throw new Error('Password update failed');
  }
};

adminSchema.methods.generateAuthToken = function(): string {
  const payload = {
    adminId: this._id,
    username: this.username,
    email: this.email
  };
  
  return jwt.sign(payload, config.jwtSecret, { 
    expiresIn: config.jwtExpiresIn || '24h' 
  } as jwt.SignOptions);
};

adminSchema.methods.updateNotificationPreferences = async function(
  preferences: Partial<IAdmin['notificationPreferences']>
): Promise<void> {
  // Validate that if SMS is enabled, phone number is provided
  if (preferences.sms === true && !preferences.phoneNumber && !this.notificationPreferences.phoneNumber) {
    throw new Error('Phone number is required when SMS notifications are enabled');
  }
  
  // Update preferences
  Object.assign(this.notificationPreferences, preferences);
  
  // If SMS is disabled, clear phone number
  if (preferences.sms === false) {
    this.notificationPreferences.phoneNumber = undefined;
  }
  
  await this.save();
};

adminSchema.methods.recordLogin = async function(): Promise<void> {
  this.lastLogin = new Date();
  await this.save();
};

// Pre-save middleware to hash password
adminSchema.pre('save', async function(next) {
  // Only hash password if it's new or modified and not already hashed
  if (this.isModified('encryptedPassword') && !this.encryptedPassword.startsWith('$argon2')) {
    try {
      this.encryptedPassword = await argon2.hash(this.encryptedPassword);
    } catch (error) {
      return next(error as Error);
    }
  }
  next();
});

// Validation schema using Joi
export const adminValidationSchema = {
  create: Joi.object({
    username: Joi.string()
      .min(3)
      .max(30)
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .required()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 30 characters',
        'any.required': 'Username is required'
      }),
    password: Joi.string()
      .min(8)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'any.required': 'Password is required'
      }),
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    notificationPreferences: Joi.object({
      email: Joi.boolean().default(true),
      sms: Joi.boolean().default(false),
      phoneNumber: Joi.string()
        .pattern(/^\+[1-9]\d{1,14}$/)
        .when('sms', {
          is: true,
          then: Joi.required(),
          otherwise: Joi.optional()
        })
        .messages({
          'string.pattern.base': 'Please provide a valid phone number in international format (+1234567890)',
          'any.required': 'Phone number is required when SMS notifications are enabled'
        })
    }).optional()
  }),
  
  update: Joi.object({
    username: Joi.string().min(3).max(30).pattern(/^[a-zA-Z0-9_-]+$/).optional(),
    password: Joi.string().min(8).optional(),
    email: Joi.string().email().optional(),
    notificationPreferences: Joi.object({
      email: Joi.boolean().optional(),
      sms: Joi.boolean().optional(),
      phoneNumber: Joi.string().pattern(/^\+[1-9]\d{1,14}$/).optional()
    }).optional()
  }).min(1), // At least one field must be provided for update

  notificationPreferences: Joi.object({
    email: Joi.boolean().optional(),
    sms: Joi.boolean().optional(),
    phoneNumber: Joi.string()
      .pattern(/^\+[1-9]\d{1,14}$/)
      .when('sms', {
        is: true,
        then: Joi.required(),
        otherwise: Joi.optional()
      })
      .messages({
        'string.pattern.base': 'Please provide a valid phone number in international format (+1234567890)',
        'any.required': 'Phone number is required when SMS notifications are enabled'
      })
  }).min(1)
};

// Static methods for CRUD operations
adminSchema.statics.createAdmin = async function(adminData: { 
  username: string; 
  password: string; 
  email: string;
  notificationPreferences?: Partial<IAdmin['notificationPreferences']>;
}) {
  // Validate input
  const { error, value } = adminValidationSchema.create.validate(adminData);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  // Check if admin already exists (by username or email)
  const existingAdmin = await this.findOne({
    $or: [
      { username: value.username },
      { email: value.email }
    ]
  });
  
  if (existingAdmin) {
    throw new Error('Admin with this username or email already exists');
  }

  // Set default notification preferences
  const defaultPreferences = {
    email: true,
    sms: false,
    phoneNumber: undefined
  };

  // Create new admin (password will be hashed by pre-save middleware)
  const admin = new this({
    username: value.username,
    encryptedPassword: value.password, // Will be hashed by pre-save hook
    email: value.email,
    notificationPreferences: { ...defaultPreferences, ...value.notificationPreferences }
  });

  return await admin.save();
};

adminSchema.statics.authenticateAdmin = async function(username: string, password: string) {
  const admin = await this.findOne({ username });
  if (!admin) {
    return null;
  }

  const isValidPassword = await admin.verifyPassword(password);
  if (!isValidPassword) {
    return null;
  }

  // Record successful login
  await admin.recordLogin();
  return admin;
};

adminSchema.statics.getAdminById = async function(adminId: string) {
  return await this.findById(adminId);
};

adminSchema.statics.updateAdmin = async function(adminId: string, updateData: any) {
  // Validate input
  const { error, value } = adminValidationSchema.update.validate(updateData);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  const admin = await this.findById(adminId);
  if (!admin) {
    throw new Error('Admin not found');
  }

  // If password is being updated, use the updatePassword method
  if (value.password) {
    await admin.updatePassword(value.password);
    delete value.password; // Remove from update data since it's handled separately
  }

  // If notification preferences are being updated, use the updateNotificationPreferences method
  if (value.notificationPreferences) {
    await admin.updateNotificationPreferences(value.notificationPreferences);
    delete value.notificationPreferences; // Remove from update data since it's handled separately
  }

  // Update other fields
  Object.assign(admin, value);
  return await admin.save();
};

// Create and export the model
export const Admin = mongoose.model<IAdminModel, IAdminModelStatic>('Admin', adminSchema);