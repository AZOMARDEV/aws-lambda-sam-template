import { Schema, model, Document, Types } from 'mongoose';


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
  accelerometer: boolean;
  gyroscope: boolean;
  magnetometer: boolean;
  proximity: boolean;
  ambientLight: boolean;
}

export interface ISecurityFlags {
  isTrusted: boolean;
  isCompromised: boolean;
  isJailbroken: boolean; // iOS
  isRooted: boolean; // Android
  hasVpn: boolean;
  hasTor: boolean;
  hasProxy: boolean;
  isEmulator: boolean;
  isDeveloperMode: boolean;
  hasDebugger: boolean;
  riskScore: number; // 0-100
  lastSecurityCheck: Date;
  threatIndicators: string[];
}

export interface IDeviceLocation {
  country?: string;
  countryCode?: string;
  region?: string;
  regionCode?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  accuracy?: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  timestamp: Date;
  source: 'gps' | 'network' | 'ip' | 'manual' | 'wifi';
  ipAddress?: string;
  timezone?: string;
  isp?: string;
  organization?: string;
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
  peakUsageHours: number[]; // Hours of day (0-23) when device is most active
  weeklyPattern: {
    dayOfWeek: number; // 0-6 (Sunday-Saturday)
    averageSessions: number;
    averageDuration: number;
  }[];
}

export interface IDeviceCompliance {
  gdprConsent: {
    given: boolean;
    date: Date;
    version: string;
    ipAddress?: string;
  };
  dataRetentionDays: number;
  allowTracking: boolean;
  allowLocationTracking: boolean;
  allowNotifications: boolean;
  privacySettings: {
    shareLocation: boolean;
    shareDeviceInfo: boolean;
    shareUsageData: boolean;
    shareBiometricData: boolean;
    allowCrossDeviceTracking: boolean;
  };
  cookiePreferences: {
    essential: boolean;
    functional: boolean;
    analytics: boolean;
    advertising: boolean;
  };
}

// Enhanced push token interface
export interface IPushToken {
  token: string;
  platform: 'fcm' | 'apns' | 'web' | 'huawei' | 'xiaomi';
  isActive: boolean;
  registeredAt: Date;
  lastUsed?: Date;
  appId?: string; // For app-specific tokens
  topics: string[]; // Firebase topics subscribed to
  environment: 'production' | 'development' | 'sandbox';
  failureCount: number;
  lastFailure?: Date;
  metadata: Record<string, any>;
}

// Network information interface
export interface INetworkInfo {
  connectionType: 'wifi' | '4g' | '5g' | '3g' | '2g' | 'ethernet' | 'unknown';
  effectiveType?: 'slow-2g' | '2g' | '3g' | '4g';
  downlink?: number; // Mbps
  rtt?: number; // ms
  saveData?: boolean;
  carrier?: string;
  mcc?: string; // Mobile Country Code
  mnc?: string; // Mobile Network Code
  timestamp: Date;
}

// Session information interface
export interface ISessionInfo {
  sessionId: string;
  startTime: Date;
  endTime?: Date;
  duration?: number; // milliseconds
  ipAddress: string;
  userAgent: string;
  referrer?: string;
  landingPage?: string;
  exitPage?: string;
  pageViews: number;
  actions: {
    type: string;
    timestamp: Date;
    data?: Record<string, any>;
  }[];
  isActive: boolean;
}

// Base interface without Document extension
export interface IDeviceBase {
  deviceId: string; // Unique device identifier
  accountId: Types.ObjectId;
  
  // Enhanced Device Information
  name?: string; // User-defined name
  type: 'desktop' | 'mobile' | 'tablet' | 'tv' | 'watch' | 'iot' | 'smartspeaker' | 'automotive' | 'unknown';
  platform: 'web' | 'ios' | 'android' | 'windows' | 'macos' | 'linux' | 'tvos' | 'watchos' | 'harmony';
  
  // System Information with more details
  os: string;
  osVersion?: string;
  browser?: string;
  browserVersion?: string;
  browserEngine?: string; // Webkit, Blink, Gecko, etc.
  appVersion?: string; // For mobile apps
  buildNumber?: string;
  
  // Hardware Information
  manufacturer?: string;
  deviceModel?: string;
  brand?: string;
  boardName?: string;
  chipset?: string;
  
  // Enhanced Device Identification
  userAgent: string;
  capabilities: IDeviceCapabilities;
  
  // Unique Identifiers (for tracking without login)
  advertisingId?: string; // IDFA (iOS) / GAID (Android)
  vendorId?: string; // IDFV (iOS)
  androidId?: string; // Android ID
  windowsId?: string; // Windows Device ID
  macAddress?: string; // MAC address (if available)
  imei?: string; // For mobile devices
  serialNumber?: string; // Device serial number
  
  // Browser/Web specific identifiers
  clientId?: string; // Google Analytics Client ID
  
  // Security
  securityFlags: ISecurityFlags;
  pushTokens: IPushToken[];
  
  // Enhanced Location with history
  locations: IDeviceLocation[];
  currentLocation?: IDeviceLocation;
  locationHistory: {
    location: IDeviceLocation;
    duration: number; // How long device was at this location (ms)
  }[];
  
  // Network Information
  networkInfo: INetworkInfo[];
  currentNetwork?: INetworkInfo;
  
  // Usage Analytics
  usage: IDeviceUsage;
  
  // Session Management
  sessions: ISessionInfo[];
  currentSession?: ISessionInfo;
  
  // Status & Management
  status: 'active' | 'inactive' | 'blocked' | 'suspicious' | 'quarantined';
  isVerified: boolean;
  isTrusted: boolean;
  isPrimary: boolean; // Is this the user's primary device
  
  // Registration & Activity
  firstSeen: Date;
  lastSeen: Date;
  registrationMethod: 'automatic' | 'manual' | 'imported' | 'migrated';
  registrationSource?: string; // Where the device was first registered
  
  // Apps that have access to this device
  authorizedApps: {
    appId: Types.ObjectId;
    permissions: string[];
    authorizedAt: Date;
    lastUsed?: Date;
    accessCount: number;
  }[];
  
  // Compliance and Privacy
  compliance: IDeviceCompliance;
  
  // Device Management
  managementProfile?: {
    isManaged: boolean;
    mdmProvider?: string;
    policies: string[];
    lastPolicyUpdate?: Date;
  };
  
  // Biometric Information (if available)
  biometrics: {
    hasFingerprint: boolean;
    hasFaceId: boolean;
    hasVoiceId: boolean;
    hasIris: boolean;
    lastBiometricAuth?: Date;
  };
  
  // Administrative
  blockedAt?: Date;
  blockedReason?: string;
  blockedBy?: Types.ObjectId; // Admin who blocked
  quarantinedAt?: Date;
  quarantineReason?: string;
  
  // Enhanced Metadata
  metadata: Record<string, any>;
  notes?: string; // Admin notes
  tags: string[]; // For categorization
  
  // Data Retention
  dataRetentionDate?: Date; // When data should be deleted
  isDataRetentionEnabled: boolean;
  
  createdAt: Date;
  updatedAt: Date;
}

// Document interface that properly extends Document
export interface IDevice extends IDeviceBase, Document {
  // Instance methods
  trust(): Promise<void>;
  block(reason: string, blockedBy?: Types.ObjectId): Promise<void>;
  quarantine(reason: string): Promise<void>;
  updateUsage(sessionDuration: number, appId: Types.ObjectId): Promise<void>;
  addLocation(location: Partial<IDeviceLocation>): Promise<void>;
  startSession(sessionData: Partial<ISessionInfo>): Promise<void>;
  endSession(sessionId: string): Promise<void>;
  updateNetworkInfo(networkInfo: Partial<INetworkInfo>): Promise<void>;
  addPushToken(tokenData: Partial<IPushToken>): Promise<void>;
  removePushToken(token: string): Promise<void>;
  updateSecurityFlags(flags: Partial<ISecurityFlags>): Promise<void>;
  calculateRiskScore(): Promise<number>;
}

// Enhanced Schemas
const ScreenSchema = new Schema({
  width: { type: Number, required: true },
  height: { type: Number, required: true },
  colorDepth: { type: Number, default: 24 },
  pixelRatio: { type: Number, default: 1 },
  resolution: String
}, { _id: false });

const HardwareSchema = new Schema({
  cpu: { type: Number, default: 1 },
  memory: { type: Number, default: 0 }, // GB
  gpu: String,
  cores: Number,
  architecture: String
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
  nfc: { type: Boolean, default: false },
  accelerometer: { type: Boolean, default: false },
  gyroscope: { type: Boolean, default: false },
  magnetometer: { type: Boolean, default: false },
  proximity: { type: Boolean, default: false },
  ambientLight: { type: Boolean, default: false }
}, { _id: false });

const SecurityFlagsSchema = new Schema<ISecurityFlags>({
  isTrusted: { type: Boolean, default: false },
  isCompromised: { type: Boolean, default: false },
  isJailbroken: { type: Boolean, default: false },
  isRooted: { type: Boolean, default: false },
  hasVpn: { type: Boolean, default: false },
  hasTor: { type: Boolean, default: false },
  hasProxy: { type: Boolean, default: false },
  isEmulator: { type: Boolean, default: false },
  isDeveloperMode: { type: Boolean, default: false },
  hasDebugger: { type: Boolean, default: false },
  riskScore: { type: Number, min: 0, max: 100, default: 0 },
  lastSecurityCheck: { type: Date, default: Date.now },
  threatIndicators: [String]
}, { _id: false });

const DeviceLocationSchema = new Schema<IDeviceLocation>({
  country: String,
  countryCode: String,
  region: String,
  regionCode: String,
  city: String,
  latitude: { type: Number, min: -90, max: 90 },
  longitude: { type: Number, min: -180, max: 180 },
  accuracy: Number,
  altitude: Number,
  speed: Number,
  heading: Number,
  timestamp: { type: Date, default: Date.now },
  source: {
    type: String,
    enum: ['gps', 'network', 'ip', 'manual', 'wifi'],
    required: true
  },
  ipAddress: String,
  timezone: String,
  isp: String,
  organization: String
}, { _id: false });

const NetworkInfoSchema = new Schema<INetworkInfo>({
  connectionType: {
    type: String,
    enum: ['wifi', '4g', '5g', '3g', '2g', 'ethernet', 'unknown'],
    required: true
  },
  effectiveType: {
    type: String,
    enum: ['slow-2g', '2g', '3g', '4g']
  },
  downlink: Number,
  rtt: Number,
  saveData: Boolean,
  carrier: String,
  mcc: String,
  mnc: String,
  timestamp: { type: Date, default: Date.now }
}, { _id: false });

const PushTokenSchema = new Schema<IPushToken>({
  token: { type: String, required: true },
  platform: {
    type: String,
    enum: ['fcm', 'apns', 'web', 'huawei', 'xiaomi'],
    required: true
  },
  isActive: { type: Boolean, default: true },
  registeredAt: { type: Date, default: Date.now },
  lastUsed: Date,
  appId: String,
  topics: [String],
  environment: {
    type: String,
    enum: ['production', 'development', 'sandbox'],
    default: 'production'
  },
  failureCount: { type: Number, default: 0 },
  lastFailure: Date,
  metadata: { type: Schema.Types.Mixed, default: {} }
}, { _id: false });

const SessionActionSchema = new Schema({
  type: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  data: Schema.Types.Mixed
}, { _id: false });

const SessionInfoSchema = new Schema<ISessionInfo>({
  sessionId: { type: String, required: true },
  startTime: { type: Date, default: Date.now },
  endTime: Date,
  duration: Number,
  ipAddress: { type: String, required: true },
  userAgent: { type: String, required: true },
  referrer: String,
  landingPage: String,
  exitPage: String,
  pageViews: { type: Number, default: 0 },
  actions: [SessionActionSchema],
  isActive: { type: Boolean, default: true }
}, { _id: false });

// Enhanced Device Schema
const DeviceSchema = new Schema<IDevice>({
  deviceId: { 
    type: String, 
    required: true, 
    unique: true,
    default: () => `dev_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  },
  accountId: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  
  // Enhanced Device Information
  name: { type: String, trim: true },
  type: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'tv', 'watch', 'iot', 'smartspeaker', 'automotive', 'unknown'],
    default: 'unknown'
  },
  platform: {
    type: String,
    enum: ['web', 'ios', 'android', 'windows', 'macos', 'linux', 'tvos', 'watchos', 'harmony'],
    required: true
  },
  
  // System Information
  os: { type: String, required: true },
  osVersion: String,
  browser: String,
  browserVersion: String,
  browserEngine: String,
  appVersion: String,
  buildNumber: String,
  
  // Hardware Information
  manufacturer: String,
  deviceModel: String,
  brand: String,
  boardName: String,
  chipset: String,
  
  // Device Identification
  userAgent: { type: String, required: true },
  capabilities: { type: DeviceCapabilitiesSchema, default: () => ({}) },
  
  // Unique Identifiers
  advertisingId: String,
  vendorId: String,
  androidId: String,
  windowsId: String,
  macAddress: String,
  imei: String,
  serialNumber: String,
  clientId: String,

  // Security
  securityFlags: { type: SecurityFlagsSchema, default: () => ({}) },
  pushTokens: [PushTokenSchema],
  
  // Location
  locations: [DeviceLocationSchema],
  currentLocation: DeviceLocationSchema,
  locationHistory: [{
    location: DeviceLocationSchema,
    duration: { type: Number, default: 0 }
  }],
  
  // Network Information
  networkInfo: [NetworkInfoSchema],
  currentNetwork: NetworkInfoSchema,
  
  // Usage Analytics (existing schema with enhancements)
  usage: {
    totalSessions: { type: Number, default: 0 },
    totalLoginTime: { type: Number, default: 0 },
    lastLogin: { type: Date, default: Date.now },
    averageSessionDuration: { type: Number, default: 0 },
    mostUsedApps: [{
      appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
      sessionCount: { type: Number, default: 0 },
      totalTime: { type: Number, default: 0 }
    }],
    dailyUsage: [{
      date: { type: Date, required: true },
      sessions: { type: Number, default: 0 },
      duration: { type: Number, default: 0 }
    }],
    peakUsageHours: [{ type: Number, min: 0, max: 23 }],
    weeklyPattern: [{
      dayOfWeek: { type: Number, min: 0, max: 6, required: true },
      averageSessions: { type: Number, default: 0 },
      averageDuration: { type: Number, default: 0 }
    }]
  },
  
  // Session Management
  sessions: [SessionInfoSchema],
  currentSession: SessionInfoSchema,
  
  // Status & Management
  status: {
    type: String,
    enum: ['active', 'inactive', 'blocked', 'suspicious', 'quarantined'],
    default: 'active'
  },
  isVerified: { type: Boolean, default: false },
  isTrusted: { type: Boolean, default: false },
  isPrimary: { type: Boolean, default: false },
  
  // Registration & Activity
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  registrationMethod: {
    type: String,
    enum: ['automatic', 'manual', 'imported', 'migrated'],
    default: 'automatic'
  },
  registrationSource: String,
  
  // Apps authorization
  authorizedApps: [{
    appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
    permissions: [String],
    authorizedAt: { type: Date, default: Date.now },
    lastUsed: Date,
    accessCount: { type: Number, default: 0 }
  }],
  
  // Enhanced Compliance
  compliance: {
    gdprConsent: {
      given: { type: Boolean, required: true },
      date: { type: Date, default: Date.now },
      version: { type: String, default: '1.0' },
      ipAddress: String
    },
    dataRetentionDays: { type: Number, default: 365 },
    allowTracking: { type: Boolean, default: false },
    allowLocationTracking: { type: Boolean, default: false },
    allowNotifications: { type: Boolean, default: false },
    privacySettings: {
      shareLocation: { type: Boolean, default: false },
      shareDeviceInfo: { type: Boolean, default: true },
      shareUsageData: { type: Boolean, default: false },
      shareBiometricData: { type: Boolean, default: false },
      allowCrossDeviceTracking: { type: Boolean, default: false }
    },
    cookiePreferences: {
      essential: { type: Boolean, default: true },
      functional: { type: Boolean, default: false },
      analytics: { type: Boolean, default: false },
      advertising: { type: Boolean, default: false }
    }
  },
  
  // Device Management
  managementProfile: {
    isManaged: { type: Boolean, default: false },
    mdmProvider: String,
    policies: [String],
    lastPolicyUpdate: Date
  },
  
  // Biometric Information
  biometrics: {
    hasFingerprint: { type: Boolean, default: false },
    hasFaceId: { type: Boolean, default: false },
    hasVoiceId: { type: Boolean, default: false },
    hasIris: { type: Boolean, default: false },
    lastBiometricAuth: Date
  },
  
  // Administrative
  blockedAt: Date,
  blockedReason: String,
  blockedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  quarantinedAt: Date,
  quarantineReason: String,
  
  // Enhanced Metadata
  metadata: { type: Schema.Types.Mixed, default: {} },
  notes: { type: String, maxlength: 2000 },
  tags: [String],
  
  // Data Retention
  dataRetentionDate: Date,
  isDataRetentionEnabled: { type: Boolean, default: true }
}, {
  timestamps: true,
  collection: 'devices'
});

// Enhanced Instance Methods
DeviceSchema.methods.trust = async function(this: IDevice): Promise<void> {
  this.isTrusted = true;
  this.isVerified = true;
  this.securityFlags.isTrusted = true;
  this.securityFlags.riskScore = Math.max(0, this.securityFlags.riskScore - 20);
  await this.save();
};

DeviceSchema.methods.block = async function(this: IDevice, reason: string, blockedBy?: Types.ObjectId): Promise<void> {
  this.status = 'blocked';
  this.blockedAt = new Date();
  this.blockedReason = reason;
  this.blockedBy = blockedBy;
  this.isTrusted = false;
  await this.save();
};

DeviceSchema.methods.quarantine = async function(this: IDevice, reason: string): Promise<void> {
  this.status = 'quarantined';
  this.quarantinedAt = new Date();
  this.quarantineReason = reason;
  this.securityFlags.riskScore = Math.min(100, this.securityFlags.riskScore + 30);
  await this.save();
};

DeviceSchema.methods.startSession = async function(this: IDevice, sessionData: Partial<ISessionInfo>): Promise<void> {
  const session: ISessionInfo = {
    sessionId: `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    startTime: new Date(),
    ipAddress: sessionData.ipAddress!,
    userAgent: sessionData.userAgent!,
    pageViews: 0,
    actions: [],
    isActive: true,
    ...sessionData
  };
  
  this.sessions.push(session);
  this.currentSession = session;
  this.lastSeen = new Date();
  
  // Keep only last 100 sessions
  if (this.sessions.length > 100) {
    this.sessions = this.sessions.slice(-100);
  }
  
  await this.save();
};

DeviceSchema.methods.endSession = async function(this: IDevice, sessionId: string): Promise<void> {
  const session = this.sessions.find(s => s.sessionId === sessionId);
  if (session) {
    session.endTime = new Date();
    session.duration = session.endTime.getTime() - session.startTime.getTime();
    session.isActive = false;
    
    if (this.currentSession?.sessionId === sessionId) {
      this.currentSession = undefined;
    }
    
    await this.updateUsage(session.duration, new Types.ObjectId()); // App ID would be provided
  }
};

DeviceSchema.methods.addPushToken = async function(this: IDevice, tokenData: Partial<IPushToken>): Promise<void> {
  // Remove existing token if it exists
  this.pushTokens = this.pushTokens.filter(t => t.token !== tokenData.token);
  
  const pushToken: IPushToken = {
    token: tokenData.token!,
    platform: tokenData.platform!,
    isActive: true,
    registeredAt: new Date(),
    topics: [],
    environment: 'production',
    failureCount: 0,
    metadata: {},
    ...tokenData
  };
  
  this.pushTokens.push(pushToken);
  await this.save();
};

DeviceSchema.methods.calculateRiskScore = async function(this: IDevice): Promise<number> {
  let riskScore = 0;
  
  // Security flags contribute to risk
  if (this.securityFlags.isJailbroken || this.securityFlags.isRooted) riskScore += 30;
  if (this.securityFlags.hasVpn) riskScore += 10;
  if (this.securityFlags.hasTor || this.securityFlags.hasProxy) riskScore += 20;
  if (this.securityFlags.isEmulator) riskScore += 25;
  if (this.securityFlags.isDeveloperMode) riskScore += 15;
  if (this.securityFlags.isCompromised) riskScore += 50;
  
  // Location inconsistencies
  if (this.locations.length > 1) {
    const recentLocations = this.locations.slice(-10);
    const countries = new Set(recentLocations.map(l => l.country).filter(Boolean));
    if (countries.size > 3) riskScore += 15; // Multiple countries recently
  }
  
  // Device trust factors
  if (!this.isVerified) riskScore += 10;
  if (!this.isTrusted) riskScore += 5;
  
  this.securityFlags.riskScore = Math.min(100, riskScore);
  this.securityFlags.lastSecurityCheck = new Date();
  
  return this.securityFlags.riskScore;
};

// Enhanced Indexes
DeviceSchema.index({ deviceId: 1 }, { unique: true });
DeviceSchema.index({ accountId: 1 });
DeviceSchema.index({ advertisingId: 1 }, { sparse: true });
DeviceSchema.index({ androidId: 1 }, { sparse: true });
DeviceSchema.index({ vendorId: 1 }, { sparse: true });
DeviceSchema.index({ imei: 1 }, { sparse: true });
DeviceSchema.index({ 'pushTokens.token': 1 });
DeviceSchema.index({ 'pushTokens.platform': 1 });
DeviceSchema.index({ 'sessions.sessionId': 1 });
DeviceSchema.index({ status: 1 });
DeviceSchema.index({ platform: 1, type: 1 });
DeviceSchema.index({ isPrimary: 1 });
DeviceSchema.index({ tags: 1 });

// Compound indexes for common queries
DeviceSchema.index({ accountId: 1, status: 1, isTrusted: 1 });
DeviceSchema.index({ accountId: 1, platform: 1, type: 1 });
DeviceSchema.index({ 'securityFlags.riskScore': 1, status: 1 });

export const Device = model<IDevice>('Device', DeviceSchema);