import { Schema, model, Document, Types } from 'mongoose';

// Interfaces
export interface IProfile {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  avatar?: string;
  bio?: string;
  dateOfBirth?: Date;
  gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
  language: string;
  timezone: string;
  country: string;
  address?: {
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
  };
}

export interface ISecurity {
  lastPasswordChange: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
  passwordHistory: string[]; // hashed passwords
  loginHistory: {
    timestamp: Date;
    ip: string;
    userAgent: string;
    deviceId?: string;
    success: boolean;
    method: 'password' | 'mfa' | 'sso'; // Track login method used
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

export interface IMfaConfig {
  enabled: boolean;
  methods: {
    sms?: {
      enabled: boolean;
      phoneNumber: string;
      verified: boolean;
    };
    email?: {
      enabled: boolean;
      verified: boolean;
    };
    totp?: {
      enabled: boolean;
      secret: string;
      backupCodes: string[];
      verified: boolean;
    };
    push?: {
      enabled: boolean;
      deviceTokens: string[];
      verified: boolean;
    };
  };
  backupCodes: {
    code: string;
    used: boolean;
    usedAt?: Date;
  }[];
  lastUsed?: Date;
}

// NEW: SSO Configuration Interface
export interface ISsoConfig {
  enabled: boolean;
  providers: {
    google?: {
      enabled: boolean;
      googleId: string;
      email: string;
      verified: boolean;
      connectedAt: Date;
    };
    facebook?: {
      enabled: boolean;
      facebookId: string;
      email: string;
      verified: boolean;
      connectedAt: Date;
    };
    github?: {
      enabled: boolean;
      githubId: string;
      username: string;
      email: string;
      verified: boolean;
      connectedAt: Date;
    };
    microsoft?: {
      enabled: boolean;
      microsoftId: string;
      email: string;
      verified: boolean;
      connectedAt: Date;
    };
    apple?: {
      enabled: boolean;
      appleId: string;
      email?: string;
      verified: boolean;
      connectedAt: Date;
    };
    linkedin?: {
      enabled: boolean;
      linkedinId: string;
      email: string;
      verified: boolean;
      connectedAt: Date;
    };
  };
  lastUsed?: {
    provider: string;
    timestamp: Date;
  };
}

// NEW: Login Settings Interface
export interface ILoginSettings {
  allowedMethods: {
    password: boolean;
    mfa: boolean;
    sso: boolean;
  };
  defaultMethod: 'password' | 'mfa' | 'sso';
  requireMfaForSensitive: boolean; // Require MFA for sensitive operations even if not default
  sessionSettings: {
    rememberMe: boolean;
    sessionDuration: number; // in minutes
    requireReauthForSensitive: boolean;
  };
  passwordPolicy: {
    enforceStrong: boolean;
    requirePeriodic: boolean;
    periodicDays?: number;
    preventReuse: boolean;
    reuseLimit?: number;
  };
}

export interface IAccount extends Document {
  email?: string;
  phone?: string;
  username?: string;
  profile: IProfile;
  password?: string; // Made optional since SSO users might not have passwords
  security: ISecurity;
  privacy: IPrivacy;
  mfaConfig: IMfaConfig;
  ssoConfig: ISsoConfig; // NEW
  loginSettings: ILoginSettings; // NEW
  isRootAccount: boolean;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
  accountStatus: 'active' | 'suspended' | 'deactivated' | 'pending_verification';
  lastLogin?: Date;
  loginCount: number;
  deactivatedAt?: Date;
  deactivationReason?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Schemas
const AddressSchema = new Schema({
  street: String,
  city: String,
  state: String,
  postalCode: String,
  country: String
}, { _id: false });

const ProfileSchema = new Schema<IProfile>({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  displayName: { type: String, trim: true },
  avatar: String,
  bio: { type: String, maxlength: 500 },
  dateOfBirth: Date,
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer_not_to_say']
  },
  language: { type: String, required: true, default: 'en' },
  timezone: { type: String, required: true, default: 'UTC' },
  country: { type: String, required: true },
  address: AddressSchema
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
  method: { 
    type: String, 
    enum: ['password', 'mfa', 'sso'],
    required: true 
  }, // NEW: Track which method was used
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
  lastPasswordChange: { type: Date, default: Date.now },
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

const MfaConfigSchema = new Schema<IMfaConfig>({
  enabled: { type: Boolean, default: false },
  methods: MfaMethodsSchema,
  backupCodes: [BackupCodeSchema],
  lastUsed: Date
}, { _id: false });

// NEW: SSO Provider Schemas
const GoogleProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  googleId: { type: String, required: true },
  email: { type: String, required: true },
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const FacebookProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  facebookId: { type: String, required: true },
  email: { type: String, required: true },
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const GithubProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  githubId: { type: String, required: true },
  username: { type: String, required: true },
  email: { type: String, required: true },
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const MicrosoftProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  microsoftId: { type: String, required: true },
  email: { type: String, required: true },
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const AppleProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  appleId: { type: String, required: true },
  email: String, // Apple allows users to hide email
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const LinkedinProviderSchema = new Schema({
  enabled: { type: Boolean, default: false },
  linkedinId: { type: String, required: true },
  email: { type: String, required: true },
  verified: { type: Boolean, default: false },
  connectedAt: { type: Date, default: Date.now }
}, { _id: false });

const SsoProvidersSchema = new Schema({
  google: GoogleProviderSchema,
  facebook: FacebookProviderSchema,
  github: GithubProviderSchema,
  microsoft: MicrosoftProviderSchema,
  apple: AppleProviderSchema,
  linkedin: LinkedinProviderSchema
}, { _id: false });

const SsoConfigSchema = new Schema<ISsoConfig>({
  enabled: { type: Boolean, default: false },
  providers: SsoProvidersSchema,
  lastUsed: {
    provider: String,
    timestamp: Date
  }
}, { _id: false });

// NEW: Login Settings Schema
const AllowedMethodsSchema = new Schema({
  password: { type: Boolean, default: true },
  mfa: { type: Boolean, default: false },
  sso: { type: Boolean, default: false }
}, { _id: false });

const SessionSettingsSchema = new Schema({
  rememberMe: { type: Boolean, default: false },
  sessionDuration: { type: Number, default: 480 }, // 8 hours in minutes
  requireReauthForSensitive: { type: Boolean, default: true }
}, { _id: false });

const PasswordPolicySchema = new Schema({
  enforceStrong: { type: Boolean, default: true },
  requirePeriodic: { type: Boolean, default: false },
  periodicDays: { type: Number, default: 90 },
  preventReuse: { type: Boolean, default: true },
  reuseLimit: { type: Number, default: 5 }
}, { _id: false });

const LoginSettingsSchema = new Schema<ILoginSettings>({
  allowedMethods: { type: AllowedMethodsSchema, default: () => ({}) },
  defaultMethod: {
    type: String,
    enum: ['password', 'mfa', 'sso'],
    default: 'password'
  },
  requireMfaForSensitive: { type: Boolean, default: false },
  sessionSettings: { type: SessionSettingsSchema, default: () => ({}) },
  passwordPolicy: { type: PasswordPolicySchema, default: () => ({}) }
}, { _id: false });

const AccountSchema = new Schema<IAccount>({
  email: {
    type: String,
    lowercase: true,
    trim: true,
    sparse: true,
    validate: {
      validator: function(v: string) {
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
      validator: function(v: string) {
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
      validator: function(v: string) {
        return !v || /^[a-zA-Z0-9_.-]+$/.test(v);
      },
      message: 'Username can only contain letters, numbers, dots, hyphens and underscores'
    }
  },
  profile: { type: ProfileSchema, required: true },
  password: { type: String }, // Made optional for SSO-only accounts
  security: { type: SecuritySchema, default: () => ({}) },
  privacy: { type: PrivacySchema, default: () => ({}) },
  mfaConfig: { type: MfaConfigSchema, default: () => ({}) },
  ssoConfig: { type: SsoConfigSchema, default: () => ({}) }, // NEW
  loginSettings: { type: LoginSettingsSchema, default: () => ({}) }, // NEW
  isRootAccount: { type: Boolean, default: false },
  isEmailVerified: { type: Boolean, default: false },
  isPhoneVerified: { type: Boolean, default: false },
  accountStatus: {
    type: String,
    enum: ['active', 'suspended', 'deactivated', 'pending_verification'],
    default: 'pending_verification'
  },
  lastLogin: Date,
  loginCount: { type: Number, default: 0 },
  deactivatedAt: Date,
  deactivationReason: String
}, {
  timestamps: true,
  collection: 'accounts'
});

// Enhanced validation
AccountSchema.pre('validate', function(next) {
  // At least one identifier required
  if (!this.email && !this.phone && !this.username) {
    return next(new Error('At least one of email, phone, or username is required'));
  }

  // Password required if password login is enabled and no SSO providers are connected
  const hasEnabledSsoProvider = this.ssoConfig?.providers && Object.values(this.ssoConfig.providers).some((provider: any) => provider?.enabled);
  
  if (this.loginSettings?.allowedMethods?.password && !this.password && !hasEnabledSsoProvider) {
    return next(new Error('Password is required when password login is enabled and no SSO providers are connected'));
  }

  // At least one login method must be enabled
  const allowedMethods = this.loginSettings?.allowedMethods;
  if (allowedMethods && !allowedMethods.password && !allowedMethods.mfa && !allowedMethods.sso) {
    return next(new Error('At least one login method must be enabled'));
  }

  // MFA must be configured if MFA login is enabled
  if (allowedMethods?.mfa && !this.mfaConfig?.enabled) {
    return next(new Error('MFA must be configured and enabled when MFA login method is allowed'));
  }

  // SSO must have at least one provider if SSO login is enabled
  if (allowedMethods?.sso && !hasEnabledSsoProvider) {
    return next(new Error('At least one SSO provider must be enabled when SSO login method is allowed'));
  }

  next();
});

// Existing indexes
AccountSchema.index({ email: 1 }, { sparse: true, unique: true });
AccountSchema.index({ phone: 1 }, { sparse: true, unique: true });
AccountSchema.index({ username: 1 }, { sparse: true, unique: true });
AccountSchema.index({ accountStatus: 1 });
AccountSchema.index({ isEmailVerified: 1 });
AccountSchema.index({ isPhoneVerified: 1 });
AccountSchema.index({ lastLogin: 1 });
AccountSchema.index({ 'security.loginHistory.timestamp': 1 });
AccountSchema.index({ 'security.lockedUntil': 1 }, { sparse: true });

// NEW: SSO-related indexes
AccountSchema.index({ 'ssoConfig.providers.google.googleId': 1 }, { sparse: true, unique: true });
AccountSchema.index({ 'ssoConfig.providers.facebook.facebookId': 1 }, { sparse: true, unique: true });
AccountSchema.index({ 'ssoConfig.providers.github.githubId': 1 }, { sparse: true, unique: true });
AccountSchema.index({ 'ssoConfig.providers.microsoft.microsoftId': 1 }, { sparse: true, unique: true });
AccountSchema.index({ 'ssoConfig.providers.apple.appleId': 1 }, { sparse: true, unique: true });
AccountSchema.index({ 'ssoConfig.providers.linkedin.linkedinId': 1 }, { sparse: true, unique: true });

// Login method tracking indexes
AccountSchema.index({ 'loginSettings.defaultMethod': 1 });
AccountSchema.index({ 'security.loginHistory.method': 1 });

export const Account = model<IAccount>('Account', AccountSchema);