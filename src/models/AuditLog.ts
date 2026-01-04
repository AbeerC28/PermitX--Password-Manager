import mongoose, { Document, Schema } from 'mongoose';
import Joi from 'joi';

// AuditLog interface based on design document
export interface IAuditLog extends Document {
  _id: mongoose.Types.ObjectId;
  action: string;
  userId?: mongoose.Types.ObjectId;
  adminId?: mongoose.Types.ObjectId;
  details: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  severity: 'info' | 'warning' | 'error';
}

// AuditLog methods interface
export interface IAuditLogMethods {
  // Instance methods can be added here if needed
}

// AuditLog model interface combining document and methods
export interface IAuditLogModel extends IAuditLog, IAuditLogMethods {}

// Static methods interface
export interface IAuditLogStatics {
  logAction(logData: {
    action: string;
    userId?: mongoose.Types.ObjectId;
    adminId?: mongoose.Types.ObjectId;
    details?: Record<string, any>;
    ipAddress: string;
    userAgent: string;
    severity?: 'info' | 'warning' | 'error';
  }): Promise<IAuditLogModel>;
  
  searchLogs(criteria: {
    action?: string;
    userId?: mongoose.Types.ObjectId;
    adminId?: mongoose.Types.ObjectId;
    severity?: 'info' | 'warning' | 'error';
    startDate?: Date;
    endDate?: Date;
    ipAddress?: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    logs: IAuditLogModel[];
    total: number;
  }>;
  
  getLogsByUser(userId: mongoose.Types.ObjectId, limit?: number): Promise<IAuditLogModel[]>;
  getLogsByAdmin(adminId: mongoose.Types.ObjectId, limit?: number): Promise<IAuditLogModel[]>;
  getLogsByAction(action: string, limit?: number): Promise<IAuditLogModel[]>;
  getLogsBySeverity(severity: 'info' | 'warning' | 'error', limit?: number): Promise<IAuditLogModel[]>;
  cleanupOldLogs(retentionDays: number): Promise<number>; // Returns count of deleted logs
  getLogStats(startDate?: Date, endDate?: Date): Promise<{
    totalLogs: number;
    logsBySeverity: Record<string, number>;
    logsByAction: Record<string, number>;
  }>;
}

// Combined model interface
export interface IAuditLogModelStatic extends mongoose.Model<IAuditLogModel>, IAuditLogStatics {}

// Mongoose schema definition
const auditLogSchema = new Schema<IAuditLogModel>(
  {
    action: {
      type: String,
      required: [true, 'Action is required'],
      trim: true,
      maxlength: [100, 'Action cannot exceed 100 characters'],
      index: true
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true
    },
    adminId: {
      type: Schema.Types.ObjectId,
      ref: 'Admin',
      index: true
    },
    details: {
      type: Schema.Types.Mixed,
      default: {}
    },
    ipAddress: {
      type: String,
      required: [true, 'IP address is required'],
      trim: true,
      validate: {
        validator: function(ip: string) {
          // Basic IP validation (IPv4 and IPv6)
          const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
          const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
          return ipv4Regex.test(ip) || ipv6Regex.test(ip) || ip === 'localhost' || ip === '127.0.0.1';
        },
        message: 'Please provide a valid IP address'
      },
      index: true
    },
    userAgent: {
      type: String,
      required: [true, 'User agent is required'],
      trim: true,
      maxlength: [500, 'User agent cannot exceed 500 characters']
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    severity: {
      type: String,
      enum: {
        values: ['info', 'warning', 'error'],
        message: 'Severity must be one of: info, warning, error'
      },
      default: 'info',
      index: true
    }
  },
  {
    timestamps: false, // We use our own timestamp field
    collection: 'auditlogs' // Explicit collection name
  }
);

// Compound indexes for efficient querying
auditLogSchema.index({ timestamp: -1, severity: 1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ adminId: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });

// Validation schema using Joi
export const auditLogValidationSchema = {
  create: Joi.object({
    action: Joi.string()
      .max(100)
      .required()
      .messages({
        'string.max': 'Action cannot exceed 100 characters',
        'any.required': 'Action is required'
      }),
    userId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .optional()
      .messages({
        'string.pattern.base': 'User ID must be a valid MongoDB ObjectId'
      }),
    adminId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .optional()
      .messages({
        'string.pattern.base': 'Admin ID must be a valid MongoDB ObjectId'
      }),
    details: Joi.object().optional(),
    ipAddress: Joi.string()
      .required()
      .messages({
        'any.required': 'IP address is required'
      }),
    userAgent: Joi.string()
      .max(500)
      .required()
      .messages({
        'string.max': 'User agent cannot exceed 500 characters',
        'any.required': 'User agent is required'
      }),
    severity: Joi.string()
      .valid('info', 'warning', 'error')
      .optional()
      .messages({
        'any.only': 'Severity must be one of: info, warning, error'
      })
  }),

  search: Joi.object({
    action: Joi.string().max(100).optional(),
    userId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).optional(),
    adminId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).optional(),
    severity: Joi.string().valid('info', 'warning', 'error').optional(),
    startDate: Joi.date().optional(),
    endDate: Joi.date().min(Joi.ref('startDate')).optional(),
    ipAddress: Joi.string().optional(),
    limit: Joi.number().integer().min(1).max(1000).default(100),
    offset: Joi.number().integer().min(0).default(0)
  })
};

// Static methods for audit logging operations
auditLogSchema.statics.logAction = async function(logData: {
  action: string;
  userId?: mongoose.Types.ObjectId;
  adminId?: mongoose.Types.ObjectId;
  details?: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  severity?: 'info' | 'warning' | 'error';
}) {
  // Validate input
  const { error, value } = auditLogValidationSchema.create.validate({
    ...logData,
    userId: logData.userId?.toString(),
    adminId: logData.adminId?.toString()
  });
  
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  // Create audit log entry
  const auditLog = new this({
    action: value.action,
    userId: value.userId ? new mongoose.Types.ObjectId(value.userId) : undefined,
    adminId: value.adminId ? new mongoose.Types.ObjectId(value.adminId) : undefined,
    details: value.details || {},
    ipAddress: value.ipAddress,
    userAgent: value.userAgent,
    severity: value.severity || 'info'
  });

  return await auditLog.save();
};

auditLogSchema.statics.searchLogs = async function(criteria: {
  action?: string;
  userId?: mongoose.Types.ObjectId;
  adminId?: mongoose.Types.ObjectId;
  severity?: 'info' | 'warning' | 'error';
  startDate?: Date;
  endDate?: Date;
  ipAddress?: string;
  limit?: number;
  offset?: number;
}) {
  // Validate search criteria
  const { error, value } = auditLogValidationSchema.search.validate({
    ...criteria,
    userId: criteria.userId?.toString(),
    adminId: criteria.adminId?.toString()
  });
  
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  // Build query
  const query: any = {};
  
  if (value.action) {
    query.action = { $regex: value.action, $options: 'i' }; // Case-insensitive search
  }
  
  if (value.userId) {
    query.userId = new mongoose.Types.ObjectId(value.userId);
  }
  
  if (value.adminId) {
    query.adminId = new mongoose.Types.ObjectId(value.adminId);
  }
  
  if (value.severity) {
    query.severity = value.severity;
  }
  
  if (value.ipAddress) {
    query.ipAddress = { $regex: value.ipAddress, $options: 'i' };
  }
  
  if (value.startDate || value.endDate) {
    query.timestamp = {};
    if (value.startDate) {
      query.timestamp.$gte = value.startDate;
    }
    if (value.endDate) {
      query.timestamp.$lte = value.endDate;
    }
  }

  // Execute query with pagination
  const [logs, total] = await Promise.all([
    this.find(query)
      .populate('userId', 'email')
      .populate('adminId', 'username email')
      .sort({ timestamp: -1 })
      .limit(value.limit)
      .skip(value.offset),
    this.countDocuments(query)
  ]);

  return { logs, total };
};

auditLogSchema.statics.getLogsByUser = async function(userId: mongoose.Types.ObjectId, limit: number = 100) {
  return await this.find({ userId })
    .populate('adminId', 'username email')
    .sort({ timestamp: -1 })
    .limit(limit);
};

auditLogSchema.statics.getLogsByAdmin = async function(adminId: mongoose.Types.ObjectId, limit: number = 100) {
  return await this.find({ adminId })
    .populate('userId', 'email')
    .sort({ timestamp: -1 })
    .limit(limit);
};

auditLogSchema.statics.getLogsByAction = async function(action: string, limit: number = 100) {
  return await this.find({ action: { $regex: action, $options: 'i' } })
    .populate('userId', 'email')
    .populate('adminId', 'username email')
    .sort({ timestamp: -1 })
    .limit(limit);
};

auditLogSchema.statics.getLogsBySeverity = async function(severity: 'info' | 'warning' | 'error', limit: number = 100) {
  return await this.find({ severity })
    .populate('userId', 'email')
    .populate('adminId', 'username email')
    .sort({ timestamp: -1 })
    .limit(limit);
};

auditLogSchema.statics.cleanupOldLogs = async function(retentionDays: number = 90) {
  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  
  const result = await this.deleteMany({
    timestamp: { $lt: cutoffDate }
  });

  return result.deletedCount;
};

auditLogSchema.statics.getLogStats = async function(startDate?: Date, endDate?: Date) {
  const matchStage: any = {};
  
  if (startDate || endDate) {
    matchStage.timestamp = {};
    if (startDate) matchStage.timestamp.$gte = startDate;
    if (endDate) matchStage.timestamp.$lte = endDate;
  }

  const pipeline: any[] = [
    ...(Object.keys(matchStage).length > 0 ? [{ $match: matchStage }] : []),
    {
      $facet: {
        totalCount: [{ $count: 'count' }],
        severityStats: [
          { $group: { _id: '$severity', count: { $sum: 1 } } }
        ],
        actionStats: [
          { $group: { _id: '$action', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 20 } // Top 20 actions
        ]
      }
    }
  ];

  const [result] = await this.aggregate(pipeline);
  
  const totalLogs = result.totalCount[0]?.count || 0;
  
  const logsBySeverity: Record<string, number> = {};
  result.severityStats.forEach((stat: any) => {
    logsBySeverity[stat._id] = stat.count;
  });
  
  const logsByAction: Record<string, number> = {};
  result.actionStats.forEach((stat: any) => {
    logsByAction[stat._id] = stat.count;
  });

  return {
    totalLogs,
    logsBySeverity,
    logsByAction
  };
};

// Create and export the model
export const AuditLog = mongoose.model<IAuditLogModel, IAuditLogModelStatic>('AuditLog', auditLogSchema);