import { Schema, model, Document, Types } from 'mongoose';

// Interfaces
export interface IDeviceFingerprint {
  canvas?: string;
  webgl?: string;
  audio?: string;
  fonts?: string[];
  plugins?: string[];
  timezone?: string;
  language?: string;
  screen?: {
    width: number;
    height: number;
    colorDepth: number;
    pixelRatio: number;
  };
  hardware?: {
    cpu: number;
    memory: number;
    gpu?: string;
  };
  hash: string; // Combined fingerprint hash
}

export interface IDeviceCapabilities {
  touchSupport: boolean;
  geolocation: boolean;
  camera: boolean;
  microphone: boolean;
  notifications: boolean;
  localStorage: boolean;
  cookies: boolean;
  webrtc: boolean;
  bluetooth: boolean;
  nfc: boolean;
}

export interface ISecurityFlags {
  isTrusted: boolean;
  isCompromised: boolean;
  isJailbroken: boolean; // iOS
  isRooted: boolean; // Android
  hasVpn: boolean;
  hasTor: boolean;
  hasProxy: boolean;
  riskScore: number; // 0-100
  lastSecurityCheck: Date;
}

export interface IDeviceLocation {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  accuracy?: number;
  timestamp: Date;
  source: 'gps' | 'network' | 'ip' | 'manual';
}

export interface IDeviceUsage {
  totalSessions: number;
  totalLoginTime: number; // milliseconds
  lastLogin: Date;
  averageSessionDuration: number; // milliseconds
  mostUsedApps: {
    appId: Types.ObjectId;
    sessionCount: number;
    totalTime: number;
  }[];
  dailyUsage: {
    date: Date;
    sessions: number;
    duration: number; // milliseconds
  }[];
}

export interface IDeviceCompliance {
  gdprConsent: {
    given: boolean;
    date: Date;
    version: string;
  };
  dataRetentionDays: number;
  allowTracking: boolean;
  allowFingerprinting: boolean;
  privacySettings: {
    shareLocation: boolean;
    shareDeviceInfo: boolean;
    shareUsageData: boolean;
  };
}

// Base interface without Document extension - this is the key fix
export interface IDeviceBase {
  deviceId: string; // Unique device identifier
  accountId: Types.ObjectId;
  
  // Device Information
  name?: string; // User-defined name
  type: 'desktop' | 'mobile' | 'tablet' | 'tv' | 'watch' | 'iot' | 'unknown';
  platform: 'web' | 'ios' | 'android' | 'windows' | 'macos' | 'linux';
  
  // System Information
  os: string;
  osVersion?: string;
  browser?: string;
  browserVersion?: string;
  appVersion?: string; // For mobile apps
  
  // Hardware Information
  manufacturer?: string;
  deviceModel?: string; // Renamed from 'model' to avoid conflict
  brand?: string;
  
  // Device Identification
  fingerprint: IDeviceFingerprint;
  userAgent: string;
  capabilities: IDeviceCapabilities;
  
  // Security
  securityFlags: ISecurityFlags;
  pushTokens: {
    token: string;
    platform: 'fcm' | 'apns' | 'web';
    isActive: boolean;
    registeredAt: Date;
    lastUsed?: Date;
  }[];
  
  // Location
  locations: IDeviceLocation[];
  currentLocation?: IDeviceLocation;
  
  // Usage Analytics
  usage: IDeviceUsage;
  
  // Status & Management
  status: 'active' | 'inactive' | 'blocked' | 'suspicious';
  isVerified: boolean;
  isTrusted: boolean;
  
  // Registration & Activity
  firstSeen: Date;
  lastSeen: Date;
  registrationMethod: 'automatic' | 'manual' | 'imported';
  
  // Apps that have access to this device
  authorizedApps: {
    appId: Types.ObjectId;
    permissions: string[];
    authorizedAt: Date;
    lastUsed?: Date;
  }[];
  
  // Compliance
  compliance: IDeviceCompliance;
  
  // Administrative
  blockedAt?: Date;
  blockedReason?: string;
  blockedBy?: Types.ObjectId; // Admin who blocked
  
  // Metadata
  metadata: Record<string, any>;
  notes?: string; // Admin notes
  
  createdAt: Date;
  updatedAt: Date;
}

// Document interface that properly extends Document
export interface IDevice extends IDeviceBase, Document {
  // Instance methods
  trust(): void;
  block(reason: string, blockedBy?: Types.ObjectId): void;
  updateUsage(sessionDuration: number, appId: Types.ObjectId): void;
  addLocation(location: Partial<IDeviceLocation>): void;
}

// Schemas
const ScreenSchema = new Schema({
  width: { type: Number, required: true },
  height: { type: Number, required: true },
  colorDepth: { type: Number, default: 24 },
  pixelRatio: { type: Number, default: 1 }
}, { _id: false });

const HardwareSchema = new Schema({
  cpu: { type: Number, default: 1 },
  memory: { type: Number, default: 0 }, // GB
  gpu: String
}, { _id: false });

const DeviceFingerprintSchema = new Schema<IDeviceFingerprint>({
  canvas: String,
  webgl: String,
  audio: String,
  fonts: [String],
  plugins: [String],
  timezone: String,
  language: String,
  screen: ScreenSchema,
  hardware: HardwareSchema,
  hash: { type: String, required: true, unique: true }
}, { _id: false });

const DeviceCapabilitiesSchema = new Schema<IDeviceCapabilities>({
  touchSupport: { type: Boolean, default: false },
  geolocation: { type: Boolean, default: false },
  camera: { type: Boolean, default: false },
  microphone: { type: Boolean, default: false },
  notifications: { type: Boolean, default: false },
  localStorage: { type: Boolean, default: false },
  cookies: { type: Boolean, default: false },
  webrtc: { type: Boolean, default: false },
  bluetooth: { type: Boolean, default: false },
  nfc: { type: Boolean, default: false }
}, { _id: false });

const SecurityFlagsSchema = new Schema<ISecurityFlags>({
  isTrusted: { type: Boolean, default: false },
  isCompromised: { type: Boolean, default: false },
  isJailbroken: { type: Boolean, default: false },
  isRooted: { type: Boolean, default: false },
  hasVpn: { type: Boolean, default: false },
  hasTor: { type: Boolean, default: false },
  hasProxy: { type: Boolean, default: false },
  riskScore: { type: Number, min: 0, max: 100, default: 0 },
  lastSecurityCheck: { type: Date, default: Date.now }
}, { _id: false });

const DeviceLocationSchema = new Schema<IDeviceLocation>({
  country: String,
  region: String,
  city: String,
  latitude: { type: Number, min: -90, max: 90 },
  longitude: { type: Number, min: -180, max: 180 },
  accuracy: Number,
  timestamp: { type: Date, default: Date.now },
  source: {
    type: String,
    enum: ['gps', 'network', 'ip', 'manual'],
    required: true
  }
}, { _id: false });

const MostUsedAppSchema = new Schema({
  appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
  sessionCount: { type: Number, default: 0 },
  totalTime: { type: Number, default: 0 }
}, { _id: false });

const DailyUsageSchema = new Schema({
  date: { type: Date, required: true },
  sessions: { type: Number, default: 0 },
  duration: { type: Number, default: 0 }
}, { _id: false });

const DeviceUsageSchema = new Schema<IDeviceUsage>({
  totalSessions: { type: Number, default: 0 },
  totalLoginTime: { type: Number, default: 0 },
  lastLogin: { type: Date, default: Date.now },
  averageSessionDuration: { type: Number, default: 0 },
  mostUsedApps: [MostUsedAppSchema],
  dailyUsage: [DailyUsageSchema]
}, { _id: false });

const PushTokenSchema = new Schema({
  token: { type: String, required: true },
  platform: {
    type: String,
    enum: ['fcm', 'apns', 'web'],
    required: true
  },
  isActive: { type: Boolean, default: true },
  registeredAt: { type: Date, default: Date.now },
  lastUsed: Date
}, { _id: false });

const AuthorizedAppSchema = new Schema({
  appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
  permissions: [String],
  authorizedAt: { type: Date, default: Date.now },
  lastUsed: Date
}, { _id: false });

const GdprConsentSchema = new Schema({
  given: { type: Boolean, required: true },
  date: { type: Date, default: Date.now },
  version: { type: String, default: '1.0' }
}, { _id: false });

const PrivacySettingsSchema = new Schema({
  shareLocation: { type: Boolean, default: false },
  shareDeviceInfo: { type: Boolean, default: true },
  shareUsageData: { type: Boolean, default: false }
}, { _id: false });

const DeviceComplianceSchema = new Schema<IDeviceCompliance>({
  gdprConsent: GdprConsentSchema,
  dataRetentionDays: { type: Number, default: 365 },
  allowTracking: { type: Boolean, default: false },
  allowFingerprinting: { type: Boolean, default: true },
  privacySettings: PrivacySettingsSchema
}, { _id: false });

const DeviceSchema = new Schema<IDevice>({
  deviceId: { 
    type: String, 
    required: true, 
    unique: true,
    default: () => `dev_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  
  // Device Information
  name: { type: String, trim: true },
  type: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'tv', 'watch', 'iot', 'unknown'],
    default: 'unknown'
  },
  platform: {
    type: String,
    enum: ['web', 'ios', 'android', 'windows', 'macos', 'linux'],
    required: true
  },
  
  // System Information
  os: { type: String, required: true },
  osVersion: String,
  browser: String,
  browserVersion: String,
  appVersion: String,
  
  // Hardware Information
  manufacturer: String,
  deviceModel: String, // Renamed from 'model' to avoid conflict
  brand: String,
  
  // Device Identification
  fingerprint: { type: DeviceFingerprintSchema, required: true },
  userAgent: { type: String, required: true },
  capabilities: { type: DeviceCapabilitiesSchema, default: () => ({}) },
  
  // Security
  securityFlags: { type: SecurityFlagsSchema, default: () => ({}) },
  pushTokens: [PushTokenSchema],
  
  // Location
  locations: [DeviceLocationSchema],
  currentLocation: DeviceLocationSchema,
  
  // Usage Analytics
  usage: { type: DeviceUsageSchema, default: () => ({}) },
  
  // Status & Management
  status: {
    type: String,
    enum: ['active', 'inactive', 'blocked', 'suspicious'],
    default: 'active'
  },
  isVerified: { type: Boolean, default: false },
  isTrusted: { type: Boolean, default: false },
  
  // Registration & Activity
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  registrationMethod: {
    type: String,
    enum: ['automatic', 'manual', 'imported'],
    default: 'automatic'
  },
  
  // Apps authorization
  authorizedApps: [AuthorizedAppSchema],
  
  // Compliance
  compliance: { type: DeviceComplianceSchema, default: () => ({}) },
  
  // Administrative
  blockedAt: Date,
  blockedReason: String,
  blockedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  
  // Metadata
  metadata: { type: Schema.Types.Mixed, default: {} },
  notes: { type: String, maxlength: 1000 }
}, {
  timestamps: true,
  collection: 'devices'
});

// Instance Methods
DeviceSchema.methods.trust = function(this: IDevice): void {
  this.isTrusted = true;
  this.isVerified = true;
  this.securityFlags.isTrusted = true;
  this.securityFlags.riskScore = Math.max(0, this.securityFlags.riskScore - 20);
};

DeviceSchema.methods.block = function(this: IDevice, reason: string, blockedBy?: Types.ObjectId): void {
  this.status = 'blocked';
  this.blockedAt = new Date();
  this.blockedReason = reason;
  this.blockedBy = blockedBy;
  this.isTrusted = false;
};

DeviceSchema.methods.updateUsage = function(this: IDevice, sessionDuration: number, appId: Types.ObjectId): void {
  this.usage.totalSessions += 1;
  this.usage.totalLoginTime += sessionDuration;
  this.usage.lastLogin = new Date();
  this.usage.averageSessionDuration = this.usage.totalLoginTime / this.usage.totalSessions;
  
  // Update most used apps
  const appUsage = this.usage.mostUsedApps.find((app: { appId: { equals: (arg0: Types.ObjectId) => any; }; }) => app.appId.equals(appId));
  if (appUsage) {
    appUsage.sessionCount += 1;
    appUsage.totalTime += sessionDuration;
  } else {
    this.usage.mostUsedApps.push({
      appId,
      sessionCount: 1,
      totalTime: sessionDuration
    });
  }
  
  // Sort and keep top 10
  this.usage.mostUsedApps.sort((a: { sessionCount: number; }, b: { sessionCount: number; }) => b.sessionCount - a.sessionCount);
  this.usage.mostUsedApps = this.usage.mostUsedApps.slice(0, 10);
  
  // Update daily usage
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const todayUsage = this.usage.dailyUsage.find((day: { date: { getTime: () => number; }; }) => 
    day.date.getTime() === today.getTime()
  );
  
  if (todayUsage) {
    todayUsage.sessions += 1;
    todayUsage.duration += sessionDuration;
  } else {
    this.usage.dailyUsage.push({
      date: today,
      sessions: 1,
      duration: sessionDuration
    });
  }
  
  // Keep only last 90 days
  this.usage.dailyUsage = this.usage.dailyUsage
    .sort((a: { date: { getTime: () => number; }; }, b: { date: { getTime: () => number; }; }) => b.date.getTime() - a.date.getTime())
    .slice(0, 90);
    
  this.lastSeen = new Date();
};

DeviceSchema.methods.addLocation = function(this: IDevice, location: Partial<IDeviceLocation>): void {
  const newLocation = {
    timestamp: new Date(),
    ...location
  } as IDeviceLocation;
  
  this.locations.push(newLocation);
  this.currentLocation = newLocation;
  
  // Keep only last 50 locations
  if (this.locations.length > 50) {
    this.locations = this.locations.slice(-50);
  }
};

// Type the schema methods
interface IDeviceMethods {
  trust(): void;
  block(reason: string, blockedBy?: Types.ObjectId): void;
  updateUsage(sessionDuration: number, appId: Types.ObjectId): void;
  addLocation(location: Partial<IDeviceLocation>): void;
}

// Create the final interface combining base interface with Document and methods
export interface IDevice extends IDeviceBase, Document, IDeviceMethods {}

// Indexes
DeviceSchema.index({ deviceId: 1 }, { unique: true });
DeviceSchema.index({ accountId: 1 });
DeviceSchema.index({ 'fingerprint.hash': 1 });
DeviceSchema.index({ status: 1 });
DeviceSchema.index({ isTrusted: 1 });
DeviceSchema.index({ isVerified: 1 });
DeviceSchema.index({ platform: 1 });
DeviceSchema.index({ type: 1 });
DeviceSchema.index({ lastSeen: 1 });
DeviceSchema.index({ firstSeen: 1 });
DeviceSchema.index({ 'securityFlags.riskScore': 1 });
DeviceSchema.index({ 'authorizedApps.appId': 1 });
DeviceSchema.index({ 'pushTokens.token': 1 });
DeviceSchema.index({ 'pushTokens.platform': 1 });

// Compound indexes
DeviceSchema.index({ accountId: 1, status: 1 });
DeviceSchema.index({ accountId: 1, isTrusted: 1 });
DeviceSchema.index({ accountId: 1, lastSeen: 1 });

// TTL index for inactive devices
DeviceSchema.index({ lastSeen: 1 }, { 
  expireAfterSeconds: 365 * 24 * 60 * 60, // 1 year
  partialFilterExpression: { 
    status: 'inactive',
    isTrusted: false
  }
});

export const Device = model<IDevice>('Device', DeviceSchema);