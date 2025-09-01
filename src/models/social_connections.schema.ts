import { Schema, model, Document, Types } from 'mongoose';

// Interfaces
export interface IProviderProfile {
  id: string;
  email?: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
  avatar?: string;
  profileUrl?: string;
  locale?: string;
  timezone?: string;
  verified?: boolean;
  raw?: Record<string, any>; // Store complete provider response
}

export interface ITokens {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt?: Date;
  scope?: string[];
}

export interface IPermissions {
  granted: string[];
  requested: string[];
  denied: string[];
  lastUpdated: Date;
}

export interface ISocialConnection extends Document {
  accountId: Types.ObjectId;
  appId: Types.ObjectId;
  provider: 'google' | 'facebook' | 'apple' | 'github' | 'twitter' | 'linkedin' | 'microsoft' | 'discord';
  providerId: string; // User ID from the provider
  providerProfile: IProviderProfile;
  tokens: ITokens;
  permissions: IPermissions;
  connectionStatus: 'active' | 'expired' | 'revoked' | 'suspended';
  metadata: {
    firstConnection: Date;
    lastSync: Date;
    syncCount: number;
    loginCount: number;
    lastLogin?: Date;
    userAgent?: string;
    ipAddress?: string;
  };
  settings: {
    autoSync: boolean;
    syncFrequency: 'realtime' | 'hourly' | 'daily' | 'manual';
    dataToSync: string[];
    notifications: {
      connectionUpdates: boolean;
      dataSync: boolean;
      securityAlerts: boolean;
    };
  };
  privacy: {
    shareProfile: boolean;
    shareEmail: boolean;
    shareConnections: boolean;
    visibleToApps: Types.ObjectId[];
  };
  security: {
    connectionMethod: 'oauth' | 'oidc' | 'saml';
    lastTokenRefresh?: Date;
    tokenRefreshCount: number;
    suspiciousActivity: {
      timestamp: Date;
      type: string;
      description: string;
      resolved: boolean;
    }[];
    ipWhitelist?: string[];
  };
  compliance: {
    dataProcessingConsent: boolean;
    consentDate: Date;
    consentVersion: string;
    dataRetentionDays: number;
    rightToPortability: boolean;
    rightToErasure: boolean;
  };
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  expiresAt?: Date;
  revokedAt?: Date;
  revokedReason?: string;
}

// Schemas
const ProviderProfileSchema = new Schema<IProviderProfile>({
  id: { type: String, required: true },
  email: String,
  name: String,
  firstName: String,
  lastName: String,
  username: String,
  avatar: String,
  profileUrl: String,
  locale: String,
  timezone: String,
  verified: Boolean,
  raw: { type: Schema.Types.Mixed, default: {} }
}, { _id: false });

const TokensSchema = new Schema<ITokens>({
  accessToken: { type: String, required: true },
  refreshToken: String,
  tokenType: { type: String, default: 'Bearer' },
  expiresAt: Date,
  scope: [String]
}, { _id: false });

const PermissionsSchema = new Schema<IPermissions>({
  granted: { type: [String], default: [] },
  requested: { type: [String], default: [] },
  denied: { type: [String], default: [] },
  lastUpdated: { type: Date, default: Date.now }
}, { _id: false });

const MetadataSchema = new Schema({
  firstConnection: { type: Date, default: Date.now },
  lastSync: { type: Date, default: Date.now },
  syncCount: { type: Number, default: 0 },
  loginCount: { type: Number, default: 0 },
  lastLogin: Date,
  userAgent: String,
  ipAddress: String
}, { _id: false });

const NotificationsSchema = new Schema({
  connectionUpdates: { type: Boolean, default: true },
  dataSync: { type: Boolean, default: false },
  securityAlerts: { type: Boolean, default: true }
}, { _id: false });

const SettingsSchema = new Schema({
  autoSync: { type: Boolean, default: true },
  syncFrequency: {
    type: String,
    enum: ['realtime', 'hourly', 'daily', 'manual'],
    default: 'daily'
  },
  dataToSync: { type: [String], default: ['profile', 'email'] },
  notifications: NotificationsSchema
}, { _id: false });

const PrivacySchema = new Schema({
  shareProfile: { type: Boolean, default: true },
  shareEmail: { type: Boolean, default: false },
  shareConnections: { type: Boolean, default: false },
  visibleToApps: [{ type: Schema.Types.ObjectId, ref: 'App' }]
}, { _id: false });

const SuspiciousActivitySchema = new Schema({
  timestamp: { type: Date, default: Date.now },
  type: { type: String, required: true },
  description: { type: String, required: true },
  resolved: { type: Boolean, default: false }
}, { _id: false });

const SecuritySchema = new Schema({
  connectionMethod: {
    type: String,
    enum: ['oauth', 'oidc', 'saml'],
    default: 'oauth'
  },
  lastTokenRefresh: Date,
  tokenRefreshCount: { type: Number, default: 0 },
  suspiciousActivity: [SuspiciousActivitySchema],
  ipWhitelist: [String]
}, { _id: false });

const ComplianceSchema = new Schema({
  dataProcessingConsent: { type: Boolean, required: true },
  consentDate: { type: Date, default: Date.now },
  consentVersion: { type: String, default: '1.0' },
  dataRetentionDays: { type: Number, default: 2555 }, // 7 years
  rightToPortability: { type: Boolean, default: true },
  rightToErasure: { type: Boolean, default: true }
}, { _id: false });

const SocialConnectionSchema = new Schema<ISocialConnection>({
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
  provider: {
    type: String,
    enum: ['google', 'facebook', 'apple', 'github', 'twitter', 'linkedin', 'microsoft', 'discord'],
    required: true
  },
  providerId: { type: String, required: true },
  providerProfile: { type: ProviderProfileSchema, required: true },
  tokens: { type: TokensSchema, required: true },
  permissions: { type: PermissionsSchema, default: () => ({}) },
  connectionStatus: {
    type: String,
    enum: ['active', 'expired', 'revoked', 'suspended'],
    default: 'active'
  },
  metadata: { type: MetadataSchema, default: () => ({}) },
  settings: { type: SettingsSchema, default: () => ({}) },
  privacy: { type: PrivacySchema, default: () => ({}) },
  security: { type: SecuritySchema, default: () => ({}) },
  compliance: { type: ComplianceSchema, required: true },
  isActive: { type: Boolean, default: true },
  expiresAt: Date,
  revokedAt: Date,
  revokedReason: String
}, {
  timestamps: true,
  collection: 'social_connections'
});

// Indexes
SocialConnectionSchema.index({ accountId: 1 });
SocialConnectionSchema.index({ appId: 1 });
SocialConnectionSchema.index({ provider: 1 });
SocialConnectionSchema.index({ providerId: 1 });
SocialConnectionSchema.index({ accountId: 1, provider: 1 }, { unique: true });
SocialConnectionSchema.index({ connectionStatus: 1 });
SocialConnectionSchema.index({ isActive: 1 });
SocialConnectionSchema.index({ expiresAt: 1 }, { sparse: true });
SocialConnectionSchema.index({ 'tokens.expiresAt': 1 }, { sparse: true });
SocialConnectionSchema.index({ 'metadata.lastLogin': 1 });
SocialConnectionSchema.index({ updatedAt: 1 });

// TTL Index for expired connections
SocialConnectionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const SocialConnection = model<ISocialConnection>('SocialConnection', SocialConnectionSchema);