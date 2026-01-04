import mongoose, { Document, Schema } from 'mongoose';
import Joi from 'joi';
import { randomBytes } from 'crypto';

// ApprovalRequest interface based on design document
export interface IApprovalRequest extends Document {
  _id: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  userEmail: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  requestedAt: Date;
  respondedAt?: Date;
  expiresAt: Date;
  adminResponse?: {
    adminId: mongoose.Types.ObjectId;
    reason?: string;
    respondedAt: Date;
  };
  accessToken?: string; // Temporary token for password access
  accessExpiresAt?: Date;
}

// ApprovalRequest methods interface
export interface IApprovalRequestMethods {
  approve(adminId: mongoose.Types.ObjectId, reason?: string): Promise<void>;
  deny(adminId: mongoose.Types.ObjectId, reason?: string): Promise<void>;
  expire(): Promise<void>;
  generateAccessToken(): Promise<string>;
  isExpired(): boolean;
  isAccessTokenValid(): boolean;
  canBeApproved(): boolean;
}

// ApprovalRequest model interface combining document and methods
export interface IApprovalRequestModel extends IApprovalRequest, IApprovalRequestMethods {}

// Static methods interface
export interface IApprovalRequestStatics {
  createRequest(userId: mongoose.Types.ObjectId, userEmail: string): Promise<IApprovalRequestModel>;
  getPendingRequests(): Promise<IApprovalRequestModel[]>;
  getRequestsByUser(userId: mongoose.Types.ObjectId): Promise<IApprovalRequestModel[]>;
  getRequestById(requestId: string): Promise<IApprovalRequestModel | null>;
  expireOldRequests(): Promise<number>; // Returns count of expired requests
  cleanupExpiredRequests(): Promise<number>; // Returns count of cleaned up requests
  hasPendingRequest(userId: mongoose.Types.ObjectId): Promise<boolean>;
}

// Combined model interface
export interface IApprovalRequestModelStatic extends mongoose.Model<IApprovalRequestModel>, IApprovalRequestStatics {}

// Mongoose schema definition
const approvalRequestSchema = new Schema<IApprovalRequestModel>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true
    },
    userEmail: {
      type: String,
      required: [true, 'User email is required'],
      lowercase: true,
      trim: true,
      index: true
    },
    status: {
      type: String,
      enum: {
        values: ['pending', 'approved', 'denied', 'expired'],
        message: 'Status must be one of: pending, approved, denied, expired'
      },
      default: 'pending',
      index: true
    },
    requestedAt: {
      type: Date,
      default: Date.now,
      index: true
    },
    respondedAt: {
      type: Date
    },
    expiresAt: {
      type: Date,
      required: [true, 'Expiration date is required'],
      index: true,
      default: function() {
        // Default to 24 hours from now as per requirements
        return new Date(Date.now() + 24 * 60 * 60 * 1000);
      }
    },
    adminResponse: {
      adminId: {
        type: Schema.Types.ObjectId,
        ref: 'Admin'
      },
      reason: {
        type: String,
        maxlength: [500, 'Reason cannot exceed 500 characters']
      },
      respondedAt: {
        type: Date
      }
    },
    accessToken: {
      type: String,
      select: false // Don't include in queries by default for security
    },
    accessExpiresAt: {
      type: Date
    }
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt
    toJSON: {
      transform: function(doc, ret) {
        // Remove sensitive data from JSON output
        delete ret.accessToken;
        return ret;
      }
    }
  }
);

// Indexes for performance
approvalRequestSchema.index({ userId: 1, status: 1 });
approvalRequestSchema.index({ status: 1, expiresAt: 1 });
approvalRequestSchema.index({ userEmail: 1, status: 1 });

// Instance methods
approvalRequestSchema.methods.approve = async function(adminId: mongoose.Types.ObjectId, reason?: string): Promise<void> {
  if (!this.canBeApproved()) {
    throw new Error('Request cannot be approved in its current state');
  }

  this.status = 'approved';
  this.respondedAt = new Date();
  this.adminResponse = {
    adminId,
    reason,
    respondedAt: new Date()
  };

  // Generate access token for password retrieval
  await this.generateAccessToken();
  
  await this.save();
};

approvalRequestSchema.methods.deny = async function(adminId: mongoose.Types.ObjectId, reason?: string): Promise<void> {
  if (this.status !== 'pending') {
    throw new Error('Only pending requests can be denied');
  }

  this.status = 'denied';
  this.respondedAt = new Date();
  this.adminResponse = {
    adminId,
    reason,
    respondedAt: new Date()
  };

  await this.save();
};

approvalRequestSchema.methods.expire = async function(): Promise<void> {
  if (this.status === 'pending') {
    this.status = 'expired';
    this.respondedAt = new Date();
    await this.save();
  }
};

approvalRequestSchema.methods.generateAccessToken = async function(): Promise<string> {
  // Generate a secure random token
  const token = randomBytes(32).toString('hex');
  
  this.accessToken = token;
  // Access token expires in 1 hour
  this.accessExpiresAt = new Date(Date.now() + 60 * 60 * 1000);
  
  return token;
};

approvalRequestSchema.methods.isExpired = function(): boolean {
  return new Date() > this.expiresAt;
};

approvalRequestSchema.methods.isAccessTokenValid = function(): boolean {
  return !!(this.accessToken && 
           this.accessExpiresAt && 
           new Date() < this.accessExpiresAt &&
           this.status === 'approved');
};

approvalRequestSchema.methods.canBeApproved = function(): boolean {
  return this.status === 'pending' && !this.isExpired();
};

// Pre-save middleware to handle automatic expiration
approvalRequestSchema.pre('save', function(next) {
  // If the request is pending and past expiration, mark as expired
  if (this.status === 'pending' && this.isExpired()) {
    this.status = 'expired';
    this.respondedAt = new Date();
  }
  next();
});

// Validation schema using Joi
export const approvalRequestValidationSchema = {
  create: Joi.object({
    userId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .required()
      .messages({
        'string.pattern.base': 'User ID must be a valid MongoDB ObjectId',
        'any.required': 'User ID is required'
      }),
    userEmail: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'User email is required'
      }),
    expiresAt: Joi.date()
      .min('now')
      .optional()
      .messages({
        'date.min': 'Expiration date must be in the future'
      })
  }),

  approve: Joi.object({
    adminId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .required()
      .messages({
        'string.pattern.base': 'Admin ID must be a valid MongoDB ObjectId',
        'any.required': 'Admin ID is required'
      }),
    reason: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Reason cannot exceed 500 characters'
      })
  }),

  deny: Joi.object({
    adminId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .required()
      .messages({
        'string.pattern.base': 'Admin ID must be a valid MongoDB ObjectId',
        'any.required': 'Admin ID is required'
      }),
    reason: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Reason cannot exceed 500 characters'
      })
  })
};

// Static methods for CRUD operations and lifecycle management
approvalRequestSchema.statics.createRequest = async function(userId: mongoose.Types.ObjectId, userEmail: string) {
  // Validate input
  const { error, value } = approvalRequestValidationSchema.create.validate({
    userId: userId.toString(),
    userEmail
  });
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  // Check if user already has a pending request
  const existingRequest = await this.findOne({
    userId,
    status: 'pending'
  });

  if (existingRequest) {
    throw new Error('User already has a pending password request');
  }

  // Create new request
  const request = new this({
    userId,
    userEmail: value.userEmail
  });

  return await request.save();
};

approvalRequestSchema.statics.getPendingRequests = async function() {
  return await this.find({ status: 'pending' })
    .populate('userId', 'email')
    .sort({ requestedAt: -1 });
};

approvalRequestSchema.statics.getRequestsByUser = async function(userId: mongoose.Types.ObjectId) {
  return await this.find({ userId })
    .sort({ requestedAt: -1 });
};

approvalRequestSchema.statics.getRequestById = async function(requestId: string) {
  return await this.findById(requestId)
    .populate('userId', 'email')
    .populate('adminResponse.adminId', 'username email');
};

approvalRequestSchema.statics.expireOldRequests = async function() {
  const result = await this.updateMany(
    {
      status: 'pending',
      expiresAt: { $lt: new Date() }
    },
    {
      $set: {
        status: 'expired',
        respondedAt: new Date()
      }
    }
  );

  return result.modifiedCount;
};

approvalRequestSchema.statics.cleanupExpiredRequests = async function() {
  // Remove expired requests older than 7 days
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  
  const result = await this.deleteMany({
    status: 'expired',
    respondedAt: { $lt: sevenDaysAgo }
  });

  return result.deletedCount;
};

approvalRequestSchema.statics.hasPendingRequest = async function(userId: mongoose.Types.ObjectId) {
  const count = await this.countDocuments({
    userId,
    status: 'pending'
  });
  
  return count > 0;
};

// Create and export the model
export const ApprovalRequest = mongoose.model<IApprovalRequestModel, IApprovalRequestModelStatic>('ApprovalRequest', approvalRequestSchema);