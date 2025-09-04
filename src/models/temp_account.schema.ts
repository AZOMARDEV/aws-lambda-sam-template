import { Schema, model, Document, Types, Model } from 'mongoose';

// Interfaces
export interface ITempProfile {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  dateOfBirth?: Date;
  gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
  language?: string;
  timezone?: string;
  country?: string;
}

export interface IRegistrationContext {
  registrationMethod: 'email' | 'phone' | 'social' | 'invitation';
  socialProvider?: 'google' | 'facebook' | 'apple' | 'github' | 'twitter' | 'linkedin';
  socialProviderId?: string;
  invitationCode?: string;
  invitedBy?: Types.ObjectId;
  referralSource?: string;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
}

export interface IVerificationRequirements {
  emailVerification: {
    required: boolean;
    completed: boolean;
    codeId?: string;
    attempts: number;
    lastAttempt?: Date;
    verifiedAt?: Date;
  };
  phoneVerification: {
    required: boolean;
    completed: boolean;
    codeId?: string;
    attempts: number;
    lastAttempt?: Date;
    verifiedAt?: Date;
  };
  socialVerification: {
    required: boolean;
    completed: boolean;
    provider?: string;
    providerId?: string;
    verifiedAt?: Date;
  };
  documentVerification: {
    required: boolean;
    completed: boolean;
    documentType?: 'passport' | 'id_card' | 'driver_license';
    documentUrl?: string;
    verifiedAt?: Date;
    verifiedBy?: Types.ObjectId;
  };
  captchaVerification: {
    required: boolean;
    completed: boolean;
    provider: 'recaptcha' | 'hcaptcha' | 'cloudflare';
    score?: number;
    verifiedAt?: Date;
  };
}

export interface IDeviceInfo {
  deviceId?: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  os: string;
  browser: string;
  userAgent: string;
  ip: string;
  location: {
    country?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  fingerprint?: {
    hash: string;
    components: Record<string, any>;
  };
}

export interface ISecurityCheck {
  riskScore: number; // 0-100
  riskFactors: string[];
  isHighRisk: boolean;
  checks: {
    emailReputation: boolean;
    phoneReputation: boolean;
    ipReputation: boolean;
    deviceReputation: boolean;
    disposableEmail: boolean;
    vpnDetected: boolean;
    torDetected: boolean;
    botDetected: boolean;
  };
  lastCheck: Date;
}

export interface IComplianceData {
  termsAccepted: {
    accepted: boolean;
    version: string;
    acceptedAt?: Date;
    ip?: string;
  };
  privacyPolicyAccepted: {
    accepted: boolean;
    version: string;
    acceptedAt?: Date;
    ip?: string;
  };
  marketingConsent: {
    email: boolean;
    sms: boolean;
    push: boolean;
    consentedAt?: Date;
    withdrawnAt?: Date;
  };
  ageVerification: {
    verified: boolean;
    method?: 'self_declared' | 'document' | 'parental_consent';
    verifiedAt?: Date;
  };
  gdprConsent: {
    given: boolean;
    version: string;
    consentedAt?: Date;
    ip?: string;
  };
}

export interface ITempAccount extends Document {
  // Identification
  tempId: string; // Unique temporary ID

  // Basic Info
  email?: string;
  phone?: string;
  username?: string;
  password?: string;
  profile?: ITempProfile;

  // Registration Context
  registrationContext: IRegistrationContext;

  // Verification Status
  verificationRequirements: IVerificationRequirements;
  overallVerificationStatus: 'pending' | 'partial' | 'completed' | 'failed';

  // Security & Device Info
  deviceInfo: IDeviceInfo;
  securityCheck: ISecurityCheck;

  // Compliance
  complianceData: IComplianceData;

  // Status & Timing
  status: 'active' | 'expired' | 'verified' | 'suspended' | 'rejected' | 'completed' | 'converted';
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date; // Auto-delete if not verified
  lastActivity: Date;

  // Migration Info
  migratedToAccountId?: Types.ObjectId;
  migratedAt?: Date;
  migrationAttempts: number;
  migrationErrors?: string[];

  // Administrative
  rejectedAt?: Date;
  rejectedBy?: Types.ObjectId;
  rejectionReason?: string;

  suspendedAt?: Date;
  suspendedBy?: Types.ObjectId;
  suspensionReason?: string;

  // Metadata
  metadata: Record<string, any>;
  notes?: string; // Admin notes

  // Audit
  auditLog: {
    timestamp: Date;
    action: string;
    details?: string;
    ip?: string;
    userAgent?: string;
    admin?: Types.ObjectId;
  }[];

  // Instance methods
  addAuditLog: (
    action: string,
    details?: string,
    ip?: string,
    userAgent?: string,
    admin?: Types.ObjectId
  ) => void;

  markVerificationComplete: (verificationType: string) => void;
  isExpired: () => boolean;
  canMigrate: () => boolean;
  reject: (reason: string, rejectedBy?: Types.ObjectId) => void;
  suspend: (reason: string, suspendedBy?: Types.ObjectId) => void;
  extend: (hours?: number) => void;
}

// Schemas
const TempProfileSchema = new Schema<ITempProfile>({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  displayName: { type: String, trim: true },
  dateOfBirth: Date,
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer_not_to_say']
  },
  language: { type: String, default: 'en' },
  timezone: { type: String, default: 'UTC' },
  country: { type: String }
}, { _id: false });

const RegistrationContextSchema = new Schema<IRegistrationContext>({
  registrationMethod: {
    type: String,
    enum: ['email', 'phone', 'social', 'invitation'],
    required: true
  },
  socialProvider: {
    type: String,
    enum: ['google', 'facebook', 'apple', 'github', 'twitter', 'linkedin']
  },
  socialProviderId: String,
  invitationCode: String,
  invitedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  referralSource: String,
  utmSource: String,
  utmMedium: String,
  utmCampaign: String
}, { _id: false });

const EmailVerificationSchema = new Schema({
  required: { type: Boolean, default: true },
  completed: { type: Boolean, default: false },
  codeId: String,
  attempts: { type: Number, default: 0 },
  lastAttempt: Date,
  verifiedAt: Date
}, { _id: false });

const PhoneVerificationSchema = new Schema({
  required: { type: Boolean, default: false },
  completed: { type: Boolean, default: false },
  codeId: String,
  attempts: { type: Number, default: 0 },
  lastAttempt: Date,
  verifiedAt: Date
}, { _id: false });

const SocialVerificationSchema = new Schema({
  required: { type: Boolean, default: false },
  completed: { type: Boolean, default: false },
  provider: String,
  providerId: String,
  verifiedAt: Date
}, { _id: false });

const DocumentVerificationSchema = new Schema({
  required: { type: Boolean, default: false },
  completed: { type: Boolean, default: false },
  documentType: {
    type: String,
    enum: ['passport', 'id_card', 'driver_license']
  },
  documentUrl: String,
  verifiedAt: Date,
  verifiedBy: { type: Schema.Types.ObjectId, ref: 'Account' }
}, { _id: false });

const CaptchaVerificationSchema = new Schema({
  required: { type: Boolean, default: true },
  completed: { type: Boolean, default: false },
  provider: {
    type: String,
    enum: ['recaptcha', 'hcaptcha', 'cloudflare'],
    default: 'recaptcha'
  },
  score: Number,
  verifiedAt: Date
}, { _id: false });

const VerificationRequirementsSchema = new Schema<IVerificationRequirements>({
  emailVerification: EmailVerificationSchema,
  phoneVerification: PhoneVerificationSchema,
  socialVerification: SocialVerificationSchema,
  documentVerification: DocumentVerificationSchema,
  captchaVerification: CaptchaVerificationSchema
}, { _id: false });

const LocationSchema = new Schema({
  country: String,
  region: String,
  city: String,
  latitude: Number,
  longitude: Number
}, { _id: false });

const FingerprintSchema = new Schema({
  hash: { type: String, required: true },
  components: { type: Schema.Types.Mixed, default: {} }
}, { _id: false });

const DeviceInfoSchema = new Schema<IDeviceInfo>({
  deviceId: String,
  deviceType: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'unknown'],
    default: 'unknown'
  },
  os: { type: String, required: true },
  browser: { type: String, required: true },
  userAgent: { type: String, required: true },
  ip: { type: String, required: true },
  location: LocationSchema,
  fingerprint: FingerprintSchema
}, { _id: false });

const SecurityChecksSchema = new Schema({
  emailReputation: { type: Boolean, default: true },
  phoneReputation: { type: Boolean, default: true },
  ipReputation: { type: Boolean, default: true },
  deviceReputation: { type: Boolean, default: true },
  disposableEmail: { type: Boolean, default: false },
  vpnDetected: { type: Boolean, default: false },
  torDetected: { type: Boolean, default: false },
  botDetected: { type: Boolean, default: false }
}, { _id: false });

const SecurityCheckSchema = new Schema<ISecurityCheck>({
  riskScore: { type: Number, min: 0, max: 100, default: 0 },
  riskFactors: [String],
  isHighRisk: { type: Boolean, default: false },
  checks: SecurityChecksSchema,
  lastCheck: { type: Date, default: Date.now }
}, { _id: false });

const TermsAcceptedSchema = new Schema({
  accepted: { type: Boolean, required: true },
  version: { type: String, required: true },
  acceptedAt: Date,
  ip: String
}, { _id: false });

const PrivacyPolicyAcceptedSchema = new Schema({
  accepted: { type: Boolean, required: true },
  version: { type: String, required: true },
  acceptedAt: Date,
  ip: String
}, { _id: false });

const MarketingConsentSchema = new Schema({
  email: { type: Boolean, default: false },
  sms: { type: Boolean, default: false },
  push: { type: Boolean, default: false },
  consentedAt: Date,
  withdrawnAt: Date
}, { _id: false });

const AgeVerificationSchema = new Schema({
  verified: { type: Boolean, default: false },
  method: {
    type: String,
    enum: ['self_declared', 'document', 'parental_consent']
  },
  verifiedAt: Date
}, { _id: false });

const GdprConsentSchema = new Schema({
  given: { type: Boolean, required: true },
  version: { type: String, required: true },
  consentedAt: Date,
  ip: String
}, { _id: false });

const ComplianceDataSchema = new Schema<IComplianceData>({
  termsAccepted: TermsAcceptedSchema,
  privacyPolicyAccepted: PrivacyPolicyAcceptedSchema,
  marketingConsent: MarketingConsentSchema,
  ageVerification: AgeVerificationSchema,
  gdprConsent: GdprConsentSchema
}, { _id: false });

const AuditLogSchema = new Schema({
  timestamp: { type: Date, default: Date.now },
  action: { type: String, required: true },
  details: String,
  ip: String,
  userAgent: String,
  admin: { type: Schema.Types.ObjectId, ref: 'Account' }
}, { _id: false });

const TempAccountSchema = new Schema<ITempAccount>({
  // Identification
  tempId: {
    type: String,
    required: true,
    unique: true,
    default: () => `tmp_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`
  },

  // Basic Info
  email: {
    type: String,
    lowercase: true,
    trim: true,
    sparse: true,
    validate: {
      validator: function (v: string) {
        return !v || /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
      },
      message: 'Invalid email format'
    }
  },
  phone: {
    type: String,
    trim: true,
    sparse: true,
    validate: {
      validator: function (v: string) {
        return !v || /^\+[1-9]\d{1,14}$/.test(v);
      },
      message: 'Invalid phone format (use E.164)'
    }
  },
  username: {
    type: String,
    lowercase: true,
    trim: true,
    sparse: true,
    minlength: 3,
    maxlength: 30
  },
  password: { type: String },
  profile: { type: TempProfileSchema },

  // Registration Context
  registrationContext: { type: RegistrationContextSchema, required: true },

  // Verification Status
  verificationRequirements: { type: VerificationRequirementsSchema, required: true },
  overallVerificationStatus: {
    type: String,
    enum: ['pending', 'partial', 'completed', 'failed'],
    default: 'pending'
  },

  // Security & Device Info
  deviceInfo: { type: DeviceInfoSchema, required: true },
  securityCheck: { type: SecurityCheckSchema, default: () => ({}) },

  // Compliance
  complianceData: { type: ComplianceDataSchema, required: true },

  // Status & Timing
  status: {
    type: String,
    enum: ['active', 'expired', 'verified', 'suspended', 'rejected', 'completed', 'converted'],
    default: 'active'
  },
  lastActivity: { type: Date, default: Date.now },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  },

  // Migration Info
  migratedToAccountId: { type: Schema.Types.ObjectId, ref: 'Account' },
  migratedAt: Date,
  migrationAttempts: { type: Number, default: 0 },
  migrationErrors: [String],

  // Administrative
  rejectedAt: Date,
  rejectedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  rejectionReason: String,

  suspendedAt: Date,
  suspendedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  suspensionReason: String,

  // Metadata
  metadata: { type: Schema.Types.Mixed, default: {} },
  notes: { type: String, maxlength: 1000 },

  // Audit
  auditLog: [AuditLogSchema]
}, {
  timestamps: true,
  collection: 'temp_users'
});

// Validation: At least one identifier required
TempAccountSchema.pre('validate', function (next) {
  if (!this.email && !this.phone && !this.username) {
    next(new Error('At least one of email, phone, or username is required'));
  } else {
    next();
  }
});

// Pre-save middleware to update verification status
TempAccountSchema.pre('save', function (next) {
  const reqs = this.verificationRequirements;

  // Check if all required verifications are completed
  const emailOk = !reqs.emailVerification.required || reqs.emailVerification.completed;
  const phoneOk = !reqs.phoneVerification.required || reqs.phoneVerification.completed;
  // const socialOk = !reqs.socialVerification.required || reqs.socialVerification.completed;
  // const docOk = !reqs.documentVerification.required || reqs.documentVerification.completed;
  // const captchaOk = !reqs.captchaVerification.required || reqs.captchaVerification.completed;

  if (emailOk && phoneOk) {
    this.overallVerificationStatus = 'completed';
    this.status = 'verified';
  } else {
    // Check if any verification is completed (partial)
    const hasAnyCompleted = reqs.emailVerification.completed ||
      reqs.phoneVerification.completed;

    this.overallVerificationStatus = hasAnyCompleted ? 'partial' : 'pending';
  }

  next();
});

// Instance Methods
TempAccountSchema.methods.addAuditLog = function (action: string, details?: string, ip?: string, userAgent?: string, admin?: Types.ObjectId): void {
  this.auditLog.push({
    timestamp: new Date(),
    action,
    details,
    ip,
    userAgent,
    admin
  });

  // Keep only last 50 audit entries
  if (this.auditLog.length > 50) {
    this.auditLog = this.auditLog.slice(-50);
  }

  this.lastActivity = new Date();
};

TempAccountSchema.methods.markVerificationComplete = function (verificationType: string): void {
  const req = this.verificationRequirements[verificationType as keyof IVerificationRequirements];
  if (req && typeof req === 'object' && 'completed' in req) {
    (req as any).completed = true;
    (req as any).verifiedAt = new Date();
    this.addAuditLog(`${verificationType}_completed`);
  }
};

TempAccountSchema.methods.isExpired = function (): boolean {
  return new Date() > this.expiresAt;
};

TempAccountSchema.methods.canMigrate = function (): boolean {
  return this.overallVerificationStatus === 'completed' &&
    this.status === 'verified' &&
    !this.isExpired() &&
    !this.migratedToAccountId;
};

TempAccountSchema.methods.reject = function (reason: string, rejectedBy?: Types.ObjectId): void {
  this.status = 'rejected';
  this.rejectedAt = new Date();
  this.rejectionReason = reason;
  this.rejectedBy = rejectedBy;
  this.addAuditLog('rejected', reason, undefined, undefined, rejectedBy);
};

TempAccountSchema.methods.suspend = function (reason: string, suspendedBy?: Types.ObjectId): void {
  this.status = 'suspended';
  this.suspendedAt = new Date();
  this.suspensionReason = reason;
  this.suspendedBy = suspendedBy;
  this.addAuditLog('suspended', reason, undefined, undefined, suspendedBy);
};

TempAccountSchema.methods.extend = function (hours: number = 24): void {
  this.expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
  this.addAuditLog(`extended_expiry_by_${hours}h`);
};

// Static Methods
TempAccountSchema.statics.cleanupExpired = function () {
  return this.deleteMany({
    $or: [
      { status: 'expired' },
      { expiresAt: { $lt: new Date() } }
    ]
  });
};

TempAccountSchema.statics.findByIdentifier = function (identifier: string) {
  return this.findOne({
    $or: [
      { email: identifier.toLowerCase() },
      { phone: identifier },
      { username: identifier.toLowerCase() }
    ],
    status: { $in: ['active', 'partial', 'verified'] }
  });
};

// Indexes
TempAccountSchema.index({ tempId: 1 }, { unique: true });
TempAccountSchema.index({ email: 1 }, { sparse: true });
TempAccountSchema.index({ phone: 1 }, { sparse: true });
TempAccountSchema.index({ username: 1 }, { sparse: true });
TempAccountSchema.index({ status: 1 });
TempAccountSchema.index({ overallVerificationStatus: 1 });
TempAccountSchema.index({ expiresAt: 1 });
TempAccountSchema.index({ createdAt: 1 });
TempAccountSchema.index({ lastActivity: 1 });
TempAccountSchema.index({ 'securityCheck.riskScore': 1 });
TempAccountSchema.index({ 'securityCheck.isHighRisk': 1 });
TempAccountSchema.index({ 'deviceInfo.ip': 1 });
TempAccountSchema.index({ migratedToAccountId: 1 }, { sparse: true });

// Compound indexes
TempAccountSchema.index({ status: 1, overallVerificationStatus: 1 });

// TTL index for automatic cleanup
TempAccountSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// TTL index for migrated users (keep for audit, then cleanup)
TempAccountSchema.index({ migratedAt: 1 }, {
  expireAfterSeconds: 30 * 24 * 60 * 60, // 30 days
  partialFilterExpression: {
    migratedAt: { $exists: true }
  }
});

export interface ITempAccountModel extends Model<ITempAccount> {
  cleanupExpired: () => Promise<any>;
  findByIdentifier: (identifier: string) => Promise<ITempAccount | null>;
}

// Then when exporting the model:
export const TempAccount = model<ITempAccount, ITempAccountModel>(
  'TempAccount',
  TempAccountSchema
);