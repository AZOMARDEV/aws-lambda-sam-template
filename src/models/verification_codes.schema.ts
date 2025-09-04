import { Schema, model, Document, Types, Model } from 'mongoose';
import bcrypt from 'bcryptjs';

// Interfaces
export interface IVerificationAttempt {
  code: string;
  timestamp: Date;
  ip?: string;
  userAgent?: string;
  success: boolean;
  failureReason?: string;
}

export interface IDeliveryInfo {
  channel: 'sms' | 'email' | 'whatsapp' | 'voice' | 'push';
  provider?: string;
  recipient: string; // phone, email, etc.
  messageId?: string; // Provider message ID
  deliveryStatus: 'pending' | 'sent' | 'delivered' | 'failed' | 'bounced';
  deliveredAt?: Date;
  failureReason?: string;
  cost?: number; // Cost in cents/currency units
}

export interface IRateLimit {
  windowStart: Date;
  windowEnd: Date;
  attemptsInWindow: number;
  maxAttemptsPerWindow: number;
  isBlocked: boolean;
  blockedUntil?: Date;
}

type NotificationType =
  | 'email_verification'
  | 'phone_verification'
  | 'password_reset'
  | 'mfa'
  | 'login_magic_link'
  | 'account_recovery'
  | 'transaction_confirmation';

type NotificationPurpose =
  | 'register'
  | 'login'
  | 'password_recovery'
  | 'security'
  | 'subscription'
  | 'transaction'
  | 'profile_update'
  | 'account_recovery'
  | 'other';


export interface IVerificationCode extends Document {
  // Identification
  codeId: string; // Unique identifier for this verification
  accountId?: Types.ObjectId; // May not exist for registration codes

  // Code Information
  code: string;
  hashedCode: string; // For security comparison
  type: NotificationType;
  purpose: NotificationPurpose;

  // Delivery
  method: 'sms' | 'email';
  deliveryInfo: IDeliveryInfo;

  // Timing
  createdAt: Date;
  expiresAt: Date;
  usedAt?: Date;

  // Status
  status: 'active' | 'used' | 'expired' | 'revoked' | 'failed';
  isUsed: boolean;

  // Attempts & Security
  attempts: IVerificationAttempt[];
  maxAttempts: number;
  remainingAttempts: number;

  // Rate Limiting
  rateLimit: IRateLimit;

  // Context
  context: {
    initiatedBy: 'user' | 'system' | 'admin';
    triggerEvent?: string; // What triggered this verification
    metadata?: Record<string, any>;
    sessionId?: string;
    deviceId?: string;
    ip?: string;
    userAgent?: string;
    location?: {
      country?: string;
      city?: string;
    };
  };

  // Security Features
  security: {
    requiresSecureChannel: boolean;
    preventBruteForce: boolean;
    logAllAttempts: boolean;
    notifyOnFailure: boolean;
    riskScore: number; // 0-100
  };

  // Linked Operations
  linkedOperations: {
    operationType: string;
    operationId?: string;
    requiresCompletion: boolean;
    completedAt?: Date;
  }[];

  // Templates & Localization
  template: {
    templateId?: Types.ObjectId;
    language: string;
    customMessage?: string;
    variables?: Record<string, any>;
  };

  // Administrative
  revokedAt?: Date;
  revokedBy?: Types.ObjectId;
  revokedReason?: string;

  updatedAt: Date;
  verify: (code: string, context: any) => boolean;
  revoke: (context: any, revokedBy?: Types.ObjectId) => void;
}

// Schemas
const VerificationAttemptSchema = new Schema<IVerificationAttempt>({
  code: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  ip: String,
  userAgent: String,
  success: { type: Boolean, required: true },
  failureReason: String
}, { _id: false });

const DeliveryInfoSchema = new Schema<IDeliveryInfo>({
  channel: {
    type: String,
    enum: ['sms', 'email', 'whatsapp', 'voice', 'push'],
    required: true
  },
  provider: String,
  recipient: { type: String, required: true },
  messageId: String,
  deliveryStatus: {
    type: String,
    enum: ['pending', 'sent', 'delivered', 'failed', 'bounced'],
    default: 'pending'
  },
  deliveredAt: Date,
  failureReason: String,
  cost: Number
}, { _id: false });

const RateLimitSchema = new Schema<IRateLimit>({
  windowStart: { type: Date, required: true },
  windowEnd: { type: Date, required: true },
  attemptsInWindow: { type: Number, default: 0 },
  maxAttemptsPerWindow: { type: Number, default: 5 },
  isBlocked: { type: Boolean, default: false },
  blockedUntil: Date
}, { _id: false });

const LocationSchema = new Schema({
  country: String,
  city: String
}, { _id: false });

const ContextSchema = new Schema({
  initiatedBy: {
    type: String,
    enum: ['user', 'system', 'admin'],
    default: 'user'
  },
  triggerEvent: String,
  metadata: { type: Schema.Types.Mixed, default: {} },
  sessionId: String,
  deviceId: String,
  ip: String,
  userAgent: String,
  location: LocationSchema
}, { _id: false });

const SecuritySchema = new Schema({
  requiresSecureChannel: { type: Boolean, default: true },
  preventBruteForce: { type: Boolean, default: true },
  logAllAttempts: { type: Boolean, default: true },
  notifyOnFailure: { type: Boolean, default: false },
  riskScore: { type: Number, min: 0, max: 100, default: 0 }
}, { _id: false });

const LinkedOperationSchema = new Schema({
  operationType: { type: String, required: true },
  operationId: String,
  requiresCompletion: { type: Boolean, default: false },
  completedAt: Date
}, { _id: false });

const TemplateSchema = new Schema({
  templateId: { type: Schema.Types.ObjectId, ref: 'MessageTemplate' },
  language: { type: String, default: 'en' },
  customMessage: String,
  variables: { type: Schema.Types.Mixed, default: {} }
}, { _id: false });

const VerificationCodeSchema = new Schema<IVerificationCode>({
  // Identification
  codeId: {
    type: String,
    required: true,
    unique: true,
    default: () => `vc_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`
  },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account' },

  // Code Information
  code: {
    type: String,
    required: true,
    validate: {
      validator: function (v: string) {
        return /^[0-9]{4,8}$/.test(v); // 4-8 digit codes
      },
      message: 'Code must be 4-8 digits'
    }
  },
  hashedCode: { type: String, required: true },
  type: {
    type: String,
    enum: [
      'email_verification',
      'phone_verification',
      'password_reset',
      'mfa',
      'login_magic_link',
      'account_recovery',
      'transaction_confirmation'
    ],
    required: true
  },
  purpose: {
    type: String,
    enum: [
      'register',
      'login',
      'password_recovery',
      'security',
      'subscription',
      'transaction',
      'profile_update',
      'account_recovery',
      'other'
    ],
    required: true
  },
  // Delivery
  method: {
    type: String,
    enum: ['sms', 'email', 'whatsapp', 'voice', 'push'],
    required: true
  },
  deliveryInfo: { type: DeliveryInfoSchema, required: true },

  // Timing
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
  },
  usedAt: Date,

  // Status
  status: {
    type: String,
    enum: ['active', 'used', 'expired', 'revoked', 'failed'],
    default: 'active'
  },
  isUsed: { type: Boolean, default: false },

  // Attempts & Security
  attempts: [VerificationAttemptSchema],
  maxAttempts: { type: Number, default: 3 },
  remainingAttempts: { type: Number, default: 3 },

  // Rate Limiting
  rateLimit: {
    type: RateLimitSchema,
    default: () => ({
      windowStart: new Date(),
      windowEnd: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      attemptsInWindow: 0,
      maxAttemptsPerWindow: 5
    })
  },

  // Context
  context: { type: ContextSchema, default: () => ({}) },

  // Security Features
  security: { type: SecuritySchema, default: () => ({}) },

  // Linked Operations
  linkedOperations: [LinkedOperationSchema],

  // Templates & Localization
  template: { type: TemplateSchema, default: () => ({}) },

  // Administrative
  revokedAt: Date,
  revokedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  revokedReason: String
}, {
  timestamps: true,
  collection: 'verification_codes'
});

// Pre-save middleware
VerificationCodeSchema.pre('save', function (next) {
  // Auto-expire if past expiration date
  if (new Date() > this.expiresAt && this.status === 'active') {
    this.status = 'expired';
  }

  // Update remaining attempts
  this.remainingAttempts = this.maxAttempts - this.attempts.length;

  // Check if should be revoked due to too many attempts
  if (this.remainingAttempts <= 0 && this.status === 'active') {
    this.status = 'failed';
  }

  next();
});

// Instance Methods
VerificationCodeSchema.methods.verify = function (inputCode: string, context: any = {}): boolean {
  const attempt: IVerificationAttempt = {
    code: inputCode,
    timestamp: new Date(),
    ip: context.ip,
    userAgent: context.userAgent,
    success: false
  };

  // Check if code is still valid
  if (this.status !== 'active') {
    attempt.failureReason = `Code is ${this.status}`;
    this.attempts.push(attempt);
    return false;
  }

  // Check expiration
  if (new Date() > this.expiresAt) {
    this.status = 'expired';
    attempt.failureReason = 'Code expired';
    this.attempts.push(attempt);
    return false;
  }

  // Check remaining attempts
  if (this.remainingAttempts <= 0) {
    this.status = 'failed';
    attempt.failureReason = 'Too many attempts';
    this.attempts.push(attempt);
    return false;
  }

  // Verify code (compare with hashed version in real implementation)
  const isValid = bcrypt.compareSync(inputCode, this.hashedCode);

  if (isValid) {
    attempt.success = true;
    this.status = 'used';
    this.isUsed = true;
    this.usedAt = new Date();

    // Complete linked operations
    this.linkedOperations.forEach((op: { requiresCompletion: any; completedAt: Date; }) => {
      if (op.requiresCompletion) {
        op.completedAt = new Date();
      }
    });
  } else {
    attempt.failureReason = 'Invalid code';
  }

  this.attempts.push(attempt);
  return isValid;
};

VerificationCodeSchema.methods.revoke = function (reason: string, revokedBy?: Types.ObjectId): void {
  this.status = 'revoked';
  this.revokedAt = new Date();
  this.revokedReason = reason;
  this.revokedBy = revokedBy;
};

VerificationCodeSchema.methods.isExpired = function (): boolean {
  return new Date() > this.expiresAt;
};

VerificationCodeSchema.methods.canRetry = function (): boolean {
  return this.remainingAttempts > 0 && this.status === 'active' && !this.isExpired();
};

VerificationCodeSchema.methods.updateDeliveryStatus = function (status: string, deliveredAt?: Date, failureReason?: string): void {
  this.deliveryInfo.deliveryStatus = status as any;
  if (deliveredAt) this.deliveryInfo.deliveredAt = deliveredAt;
  if (failureReason) this.deliveryInfo.failureReason = failureReason;

  if (status === 'failed' || status === 'bounced') {
    this.status = 'failed';
  }
};

// Static Methods
VerificationCodeSchema.statics.generateCode = function (length: number = 6): string {
  return Math.floor(Math.random() * Math.pow(10, length))
    .toString()
    .padStart(length, '0');
};

VerificationCodeSchema.statics.hashCode = function (code: string): string {
  return bcrypt.hashSync(code, 12);
};

VerificationCodeSchema.statics.findActiveCode = function (accountId: Types.ObjectId, type: string, method: string) {
  return this.findOne({
    accountId,
    type,
    method,
    status: 'active',
    expiresAt: { $gt: new Date() }
  }).sort({ createdAt: -1 });
};

VerificationCodeSchema.statics.cleanupExpired = function () {
  return this.updateMany(
    {
      status: 'active',
      expiresAt: { $lt: new Date() }
    },
    {
      $set: { status: 'expired' }
    }
  );
};

// Indexes
VerificationCodeSchema.index({ codeId: 1 }, { unique: true });
VerificationCodeSchema.index({ accountId: 1 });
VerificationCodeSchema.index({ accountId: 1, type: 1, method: 1 });
VerificationCodeSchema.index({ status: 1 });
VerificationCodeSchema.index({ expiresAt: 1 });
VerificationCodeSchema.index({ createdAt: 1 });
VerificationCodeSchema.index({ 'deliveryInfo.recipient': 1 });
VerificationCodeSchema.index({ 'deliveryInfo.messageId': 1 });
VerificationCodeSchema.index({ 'context.sessionId': 1 });
VerificationCodeSchema.index({ 'context.deviceId': 1 });
VerificationCodeSchema.index({ 'context.ip': 1 });

// Compound indexes for common queries
VerificationCodeSchema.index({ accountId: 1, status: 1, expiresAt: 1 });
VerificationCodeSchema.index({ 'deliveryInfo.recipient': 1, method: 1, status: 1 });

// TTL index for automatic cleanup of old codes
VerificationCodeSchema.index({ expiresAt: 1 }, {
  expireAfterSeconds: 24 * 60 * 60 // Delete 24 hours after expiration
});

// TTL index for used codes (keep for audit purposes, then clean up)
VerificationCodeSchema.index({ usedAt: 1 }, {
  expireAfterSeconds: 30 * 24 * 60 * 60, // Delete used codes after 30 days
  partialFilterExpression: {
    status: 'used',
    usedAt: { $exists: true }
  }
});

// Validation
VerificationCodeSchema.pre('validate', function (next) {
  // Ensure expiresAt is in the future for new codes
  if (this.isNew && this.expiresAt <= new Date()) {
    next(new Error('Expiration date must be in the future'));
    return;
  }

  // Validate code format based on type
  if (this.type === 'mfa' && !/^[0-9]{6}$/.test(this.code)) {
    next(new Error('MFA codes must be 6 digits'));
    return;
  }

  next();
});

export interface IVerificationCodeModel extends Model<IVerificationCode> {
  cleanupExpired: () => Promise<any>;
  findActiveCode: (accountId: Types.ObjectId, type: string, method: string) => Promise<IVerificationCode | null>;
  generateCode: (length?: number) => string;
  hashCode: (code: string) => string;
}

// Then when exporting the model:
export const VerificationCode = model<IVerificationCode, IVerificationCodeModel>(
  'VerificationCode',
  VerificationCodeSchema
);

