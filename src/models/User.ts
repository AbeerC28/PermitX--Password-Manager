import mongoose, { Document, Schema } from 'mongoose';
import * as argon2 from 'argon2';
import Joi from 'joi';

// User interface based on design document
export interface IUser extends Document {
  _id: mongoose.Types.ObjectId;
  email: string;
  encryptedPassword: string;
  createdAt: Date;
  updatedAt: Date;
  isActive: boolean;
  lastPasswordUpdate: Date;
}

// User methods interface
export interface IUserMethods {
  verifyPassword(password: string): Promise<boolean>;
  updatePassword(newPassword: string): Promise<void>;
}

// User model interface combining document and methods
export interface IUserModel extends IUser, IUserMethods {}

// Static methods interface
export interface IUserStatics {
  createUser(userData: { email: string; password: string }): Promise<IUserModel>;
  updateUser(userId: string, updateData: any): Promise<IUserModel>;
  deleteUser(userId: string): Promise<IUserModel | null>;
  getAllUsers(includeInactive?: boolean): Promise<IUserModel[]>;
  getUserByEmail(email: string): Promise<IUserModel | null>;
}

// Combined model interface
export interface IUserModelStatic extends mongoose.Model<IUserModel>, IUserStatics {}

// Mongoose schema definition
const userSchema = new Schema<IUserModel>(
  {
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
    encryptedPassword: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters long']
    },
    isActive: {
      type: Boolean,
      default: true
    },
    lastPasswordUpdate: {
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
userSchema.methods.verifyPassword = async function(password: string): Promise<boolean> {
  try {
    return await argon2.verify(this.encryptedPassword, password);
  } catch (error) {
    throw new Error('Password verification failed');
  }
};

userSchema.methods.updatePassword = async function(newPassword: string): Promise<void> {
  try {
    this.encryptedPassword = await argon2.hash(newPassword);
    this.lastPasswordUpdate = new Date();
    await this.save();
  } catch (error) {
    throw new Error('Password update failed');
  }
};

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash password if it's new or modified and not already hashed
  if (this.isModified('encryptedPassword') && !this.encryptedPassword.startsWith('$argon2')) {
    try {
      this.encryptedPassword = await argon2.hash(this.encryptedPassword);
      this.lastPasswordUpdate = new Date();
    } catch (error) {
      return next(error as Error);
    }
  }
  next();
});

// Validation schema using Joi
export const userValidationSchema = {
  create: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(8)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'any.required': 'Password is required'
      })
  }),
  
  update: Joi.object({
    email: Joi.string().email().optional(),
    password: Joi.string().min(8).optional(),
    isActive: Joi.boolean().optional()
  }).min(1) // At least one field must be provided for update
};

// Static methods for CRUD operations
userSchema.statics.createUser = async function(userData: { email: string; password: string }) {
  // Validate input
  const { error, value } = userValidationSchema.create.validate(userData);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  // Check if user already exists
  const existingUser = await this.findOne({ email: value.email });
  if (existingUser) {
    throw new Error('User with this email already exists');
  }

  // Create new user (password will be hashed by pre-save middleware)
  const user = new this({
    email: value.email,
    encryptedPassword: value.password // Will be hashed by pre-save hook
  });

  return await user.save();
};

userSchema.statics.updateUser = async function(userId: string, updateData: any) {
  // Validate input
  const { error, value } = userValidationSchema.update.validate(updateData);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }

  const user = await this.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // If password is being updated, use the updatePassword method
  if (value.password) {
    await user.updatePassword(value.password);
    delete value.password; // Remove from update data since it's handled separately
  }

  // Update other fields
  Object.assign(user, value);
  return await user.save();
};

userSchema.statics.deleteUser = async function(userId: string) {
  const user = await this.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  return await this.findByIdAndDelete(userId);
};

userSchema.statics.getAllUsers = async function(includeInactive: boolean = false) {
  const filter = includeInactive ? {} : { isActive: true };
  return await this.find(filter).select('-encryptedPassword');
};

userSchema.statics.getUserByEmail = async function(email: string) {
  return await this.findOne({ email: email.toLowerCase() });
};

// Create and export the model
export const User = mongoose.model<IUserModel, IUserModelStatic>('User', userSchema);