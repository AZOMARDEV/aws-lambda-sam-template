import { Schema, model, Document, Types } from 'mongoose';

// Nested Interfaces
interface IProfilePicture {
  url: string;
  verified?: boolean;
  lastUpdated?: Date;
}

// Interfaces
export interface IProfile {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  bio?: string;
  dateOfBirth?: Date;
  gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
  profilePicture?: IProfilePicture;
  language: string;
  timezone: string;
}

export interface ISecurity {
  lastPasswordChange?: Date; // Change to optional since password might not exist
  failedLoginAttempts: number;
  lockedUntil?: Date;
  passwordHistory: string[]; // hashed passwords
  loginHistory: {
    timestamp: Date;
    ip: string;
    userAgent: string;
    deviceId?: string;
    success: boolean;
    location?: {
      country?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
    };
  }[];
  trustedDevices: string[]; // device IDs
  suspiciousActivity: {
    timestamp: Date;
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    resolved: boolean;
  }[];
}

export interface IPrivacy {
  profileVisibility: 'public' | 'private' | 'friends_only';
  shareDataWithApps: boolean;
  allowMarketing: boolean;
  cookieConsent: {
    essential: boolean;
    analytics: boolean;
    marketing: boolean;
    consentDate: Date;
  };
  dataProcessingConsent: {
    given: boolean;
    date: Date;
    withdrawnAt?: Date;
  };
  rightToBeForgotten: boolean;
}

interface ICoordinates {
  latitude: number;
  longitude: number;
}

interface IAddress {
  street?: string;
  unit?: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  timezone?: string;
  coordinates?: ICoordinates;
  verified?: boolean;
}

interface IStatusHistory {
  status: 'active' | 'deactivated' | 'suspended' | 'banned' | 'pending_verification';
  reason: string;
  timestamp: Date;
  changedBy: string;
}

interface IAccountStatus {
  status: 'active' | 'deactivated' | 'suspended' | 'banned' | 'pending_verification';
  statusReason?: string;
  lastStatusChange?: Date;
  statusHistory?: IStatusHistory[];
  isComplete?: boolean;
  verificationLevel: string;
  lastActive?: Date;
  registrationDate: Date;
  accountType: string;
  membershipTier: string;
  strikeCount?: number;
}

export interface IAccount extends Document {
  email?: string;
  phone?: string;
  username?: string;
  profile: IProfile;
  address?: IAddress;
  password?: string;
  hasPassword: boolean;
  security: ISecurity;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
  accountStatus: IAccountStatus;
  lastLogin?: Date;
  loginCount: number;
  createdAt: Date;
  updatedAt: Date;
}


const ProfileSchema = new Schema<IProfile>({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  displayName: { type: String, trim: true },
  bio: { type: String, maxlength: 500 },
  dateOfBirth: Date,
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer_not_to_say']
  },
  language: { type: String, required: true, default: 'en' },
  timezone: { type: String, required: true, default: 'UTC' },
}, { _id: false });

const LocationSchema = new Schema({
  country: String,
  city: String,
  latitude: Number,
  longitude: Number
}, { _id: false });

const LoginHistorySchema = new Schema({
  timestamp: { type: Date, default: Date.now },
  ip: { type: String, required: true },
  userAgent: String,
  deviceId: String,
  success: { type: Boolean, required: true },
  location: LocationSchema
}, { _id: false });

const SuspiciousActivitySchema = new Schema({
  timestamp: { type: Date, default: Date.now },
  type: { type: String, required: true },
  description: { type: String, required: true },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high'],
    required: true
  },
  resolved: { type: Boolean, default: false }
}, { _id: false });

const SecuritySchema = new Schema<ISecurity>({
  lastPasswordChange: Date, // Remove default: Date.now since it's now optional
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: Date,
  passwordHistory: [String],
  loginHistory: { type: [LoginHistorySchema], default: [] },
  trustedDevices: [String],
  suspiciousActivity: { type: [SuspiciousActivitySchema], default: [] }
}, { _id: false });

const CookieConsentSchema = new Schema({
  essential: { type: Boolean, default: true },
  analytics: { type: Boolean, default: false },
  marketing: { type: Boolean, default: false },
  consentDate: { type: Date, default: Date.now }
}, { _id: false });

const DataProcessingConsentSchema = new Schema({
  given: { type: Boolean, required: true },
  date: { type: Date, default: Date.now },
  withdrawnAt: Date
}, { _id: false });

const PrivacySchema = new Schema<IPrivacy>({
  profileVisibility: {
    type: String,
    enum: ['public', 'private', 'friends_only'],
    default: 'public'
  },
  shareDataWithApps: { type: Boolean, default: true },
  allowMarketing: { type: Boolean, default: false },
  cookieConsent: CookieConsentSchema,
  dataProcessingConsent: DataProcessingConsentSchema,
  rightToBeForgotten: { type: Boolean, default: false }
}, { _id: false });

const MfaMethodsSchema = new Schema({
  sms: {
    enabled: { type: Boolean, default: false },
    phoneNumber: String,
    verified: { type: Boolean, default: false }
  },
  email: {
    enabled: { type: Boolean, default: false },
    verified: { type: Boolean, default: false }
  },
  totp: {
    enabled: { type: Boolean, default: false },
    secret: String,
    backupCodes: [String],
    verified: { type: Boolean, default: false }
  },
  push: {
    enabled: { type: Boolean, default: false },
    deviceTokens: [String],
    verified: { type: Boolean, default: false }
  }
}, { _id: false });

const BackupCodeSchema = new Schema({
  code: { type: String, required: true },
  used: { type: Boolean, default: false },
  usedAt: Date
}, { _id: false });

const AccountSchema = new Schema<IAccount>({
  email: {
    type: String,
    lowercase: true,
    trim: true,
    sparse: true, // allows multiple null values
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
    maxlength: 30,
    validate: {
      validator: function (v: string) {
        return !v || /^[a-zA-Z0-9_.-]+$/.test(v);
      },
      message: 'Username can only contain letters, numbers, dots, hyphens and underscores'
    }
  },
  profile: { type: ProfileSchema, required: true },
  password: {
    type: String,
    required: false // Change from true to false
  },
  hasPassword: {
    type: Boolean,
    default: false // Track if user has set a password
  },
  // connectedApps: [ConnectedAppSchema],
  security: { type: SecuritySchema, default: () => ({}) },
  isEmailVerified: { type: Boolean, default: false },
  isPhoneVerified: { type: Boolean, default: false },
  accountStatus: {
    status: {
      type: String,
      enum: ['pending_verification', 'active', 'suspended', 'banned'],
      index: true
    },
    statusReason: {
      type: String
    },
    lastStatusChange: {
      type: Date,
      default: Date.now
    },
    statusHistory: [{
      status: {
        type: String,
        enum: ['pending_verification', 'active', 'suspended', 'banned']
      },
      reason: String,
      timestamp: {
        type: Date,
        default: Date.now
      },
      changedBy: {
        type: String,
        default: 'system'
      }
    }],
    isComplete: {
      type: Boolean,
      default: true,
      index: true
    },
    verificationLevel: {
      type: String,
      required: true,
      index: true
    },
    lastActive: {
      type: Date,
      index: true
    },
    registrationDate: {
      type: Date,
      required: true,
      default: Date.now
    },
    accountType: {
      type: String,
      required: true,
      enum: ['standard', 'individual', 'business', 'agency'],
      index: true
    },
    membershipTier: {
      type: String,
      required: true,
      enum: ['basic', 'premium', 'gold', 'platinum'],
      index: true
    },
    strikeCount: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  lastLogin: Date,
  loginCount: { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'accounts'
});

// Validation: At least one identifier required
AccountSchema.pre('validate', function (next) {
  // Existing validation
  if (!this.email && !this.phone && !this.username) {
    next(new Error('At least one of email, phone, or username is required'));
    return;
  }

  // Update hasPassword flag
  this.hasPassword = !!this.password;

  next();
});

// Indexes
AccountSchema.index({ email: 1 }, { sparse: true, unique: true });
AccountSchema.index({ phone: 1 }, { sparse: true, unique: true });
AccountSchema.index({ username: 1 }, { sparse: true, unique: true });
AccountSchema.index({ "accountStatus.status": 1 });
AccountSchema.index({ "accountStatus.lastActive": -1 });
AccountSchema.index({ "accountStatus.registrationDate": 1 });

AccountSchema.index({ isEmailVerified: 1 });
AccountSchema.index({ isPhoneVerified: 1 });
AccountSchema.index({ lastLogin: 1 });
AccountSchema.index({ 'security.loginHistory.timestamp': 1 });
AccountSchema.index({ 'security.lockedUntil': 1 }, { sparse: true });

export const Account = model<IAccount>('Account', AccountSchema);