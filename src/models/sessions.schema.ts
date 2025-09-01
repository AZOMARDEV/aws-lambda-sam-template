import { Schema, model, Document, Types } from 'mongoose';

// Interfaces
export interface IDeviceInfo {
  deviceId?: string;
  deviceName?: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'tv' | 'watch' | 'unknown';
  os: string;
  osVersion?: string;
  browser: string;
  browserVersion?: string;
  userAgent: string;
  screenResolution?: string;
  timezone?: string;
  language?: string;
}

export interface ILocation {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  organization?: string;
  isVpn?: boolean;
  isTor?: boolean;
}

export interface ISecurityContext {
  riskScore: number; // 0-100, higher = more risky
  riskFactors: string[];
  isTrusted: boolean;
  requiresMfa: boolean;
  mfaCompleted: boolean;
  mfaMethod?: string;
  authenticationMethod: 'password' | 'social' | 'magic_link' | 'biometric';
  strongAuthentication: boolean;
}

export interface ISessionActivity {
  timestamp: Date;
  action: string;
  endpoint?: string;
  method?: string;
  statusCode?: number;
  responseTime?: number;
  userAgent?: string;
  ip?: string;
}

export interface IRefreshToken {
  token: string;
  expiresAt: Date;
  isRevoked: boolean;
  revokedAt?: Date;
  revokedReason?: string;
  family: string; // Token family for rotation
}

export interface ISession extends Document {
  sessionId: string;
  accountId: Types.ObjectId;
  deviceInfo: IDeviceInfo;
  location: ILocation;
  securityContext: ISecurityContext;

  // Session timing
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  timeoutAt: Date; // Inactivity timeout

  // Session state
  status: 'active' | 'expired' | 'terminated' | 'suspicious';
  isActive: boolean;
  isPersistent: boolean; // Remember me

  // Authentication
  accessToken: string;
  refreshTokens: IRefreshToken[];
  tokenFamily: string;

  // Permissions & Scope
  roles: string[];
  permissions: string[];
  scopes: string[];

  // Activity tracking
  activities: ISessionActivity[];
  requestCount: number;
  dataTransferred: number; // bytes

  // Concurrency
  concurrentSessions: number;
  maxConcurrentAllowed: number;

  // Termination
  terminatedAt?: Date;
  terminationReason?: 'logout' | 'timeout' | 'admin' | 'security' | 'max_sessions' | 'token_theft';
  terminatedBy?: 'user' | 'system' | 'admin';

  // Metadata
  metadata: Record<string, any>;

  updatedAt: Date;

  addActivity: (activity: Partial<ISessionActivity>) => void;
  terminate: (reason: string, terminatedBy: string) => void;

}

// Schemas
const DeviceInfoSchema = new Schema<IDeviceInfo>({
  deviceId: String,
  deviceName: String,
  deviceType: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'tv', 'watch', 'unknown'],
    default: 'unknown'
  },
  os: { type: String, required: true },
  osVersion: String,
  browser: { type: String, required: true },
  browserVersion: String,
  userAgent: { type: String, required: true },
  screenResolution: String,
  timezone: String,
  language: String
}, { _id: false });

const LocationSchema = new Schema<ILocation>({
  ip: { type: String, required: true },
  country: String,
  region: String,
  city: String,
  latitude: Number,
  longitude: Number,
  isp: String,
  organization: String,
  isVpn: { type: Boolean, default: false },
  isTor: { type: Boolean, default: false }
}, { _id: false });

const SecurityContextSchema = new Schema<ISecurityContext>({
  riskScore: { type: Number, min: 0, max: 100, default: 0 },
  riskFactors: [String],
  isTrusted: { type: Boolean, default: false },
  requiresMfa: { type: Boolean, default: false },
  mfaCompleted: { type: Boolean, default: false },
  mfaMethod: String,
  authenticationMethod: {
    type: String,
    enum: ['password', 'social', 'magic_link', 'biometric'],
    required: true
  },
  strongAuthentication: { type: Boolean, default: false }
}, { _id: false });

const SessionActivitySchema = new Schema<ISessionActivity>({
  timestamp: { type: Date, default: Date.now },
  action: { type: String, required: true },
  endpoint: String,
  method: String,
  statusCode: Number,
  responseTime: Number,
  userAgent: String,
  ip: String
}, { _id: false });

const RefreshTokenSchema = new Schema<IRefreshToken>({
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  isRevoked: { type: Boolean, default: false },
  revokedAt: Date,
  revokedReason: String,
  family: { type: String, required: true }
}, { _id: false });

const SessionSchema = new Schema<ISession>({
  sessionId: {
    type: String,
    required: true,
    unique: true,
    default: () => `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  deviceInfo: { type: DeviceInfoSchema, required: true },
  location: { type: LocationSchema, required: true },
  securityContext: { type: SecurityContextSchema, required: true },

  // Session timing
  lastActivityAt: { type: Date, default: Date.now },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  },
  timeoutAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
  },

  // Session state
  status: {
    type: String,
    enum: ['active', 'expired', 'terminated', 'suspicious'],
    default: 'active'
  },
  isActive: { type: Boolean, default: true },
  isPersistent: { type: Boolean, default: false },

  // Authentication
  accessToken: { type: String, required: true },
  refreshTokens: [RefreshTokenSchema],
  tokenFamily: {
    type: String,
    default: () => `fam_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
  },

  // Permissions & Scope
  roles: [String],
  permissions: [String],
  scopes: [String],

  // Activity tracking
  activities: [SessionActivitySchema],
  requestCount: { type: Number, default: 0 },
  dataTransferred: { type: Number, default: 0 },

  // Concurrency
  concurrentSessions: { type: Number, default: 1 },
  maxConcurrentAllowed: { type: Number, default: 3 },

  // Termination
  terminatedAt: Date,
  terminationReason: {
    type: String,
    enum: ['logout', 'timeout', 'admin', 'security', 'max_sessions', 'token_theft']
  },
  terminatedBy: {
    type: String,
    enum: ['user', 'system', 'admin']
  },

  // Metadata
  metadata: { type: Schema.Types.Mixed, default: {} }
}, {
  timestamps: true,
  collection: 'sessions'
});

// Pre-save middleware to update timeoutAt on activity
SessionSchema.pre('save', function (next) {
  if (this.isModified('lastActivityAt') && this.isActive) {
    // Extend timeout by 30 minutes from last activity
    this.timeoutAt = new Date(this.lastActivityAt.getTime() + 30 * 60 * 1000);
  }
  next();
});

// Methods
SessionSchema.methods.isExpired = function (): boolean {
  return new Date() > this.expiresAt;
};

SessionSchema.methods.isTimedOut = function (): boolean {
  return new Date() > this.timeoutAt;
};

SessionSchema.methods.extend = function (minutes: number = 30): void {
  this.lastActivityAt = new Date();
  this.timeoutAt = new Date(Date.now() + minutes * 60 * 1000);
};

SessionSchema.methods.terminate = function (reason: string, terminatedBy: string = 'user'): void {
  this.status = 'terminated';
  this.isActive = false;
  this.terminatedAt = new Date();
  this.terminationReason = reason;
  this.terminatedBy = terminatedBy;
};

SessionSchema.methods.addActivity = function (activity: Partial<ISessionActivity>): void {
  this.activities.push({
    timestamp: new Date(),
    ...activity
  } as ISessionActivity);

  this.requestCount += 1;
  this.lastActivityAt = new Date();

  // Keep only last 100 activities
  if (this.activities.length > 100) {
    this.activities = this.activities.slice(-100);
  }
};

// Indexes
SessionSchema.index({ sessionId: 1 }, { unique: true });
SessionSchema.index({ accountId: 1 });
SessionSchema.index({ status: 1 });
SessionSchema.index({ isActive: 1 });
SessionSchema.index({ expiresAt: 1 });
SessionSchema.index({ timeoutAt: 1 });
SessionSchema.index({ lastActivityAt: 1 });
SessionSchema.index({ 'location.ip': 1 });
SessionSchema.index({ 'deviceInfo.deviceId': 1 });
SessionSchema.index({ 'securityContext.riskScore': 1 });
SessionSchema.index({ tokenFamily: 1 });
SessionSchema.index({ createdAt: 1 });

// TTL indexes for cleanup
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-delete expired sessions
SessionSchema.index({ terminatedAt: 1 }, {
  expireAfterSeconds: 30 * 24 * 60 * 60, // Delete terminated sessions after 30 days
  partialFilterExpression: { terminatedAt: { $exists: true } }
});

// Compound indexes for common queries
SessionSchema.index({ accountId: 1, isActive: 1, status: 1 });

export const Session = model<ISession>('Session', SessionSchema);