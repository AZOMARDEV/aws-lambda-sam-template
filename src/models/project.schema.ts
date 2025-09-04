import mongoose, { Schema, Document } from "mongoose";

/* ---------- AUTHENTICATION FLOW TYPES ---------- */
type LoginMethod = "EMAIL" | "PHONE" | "USERNAME";
type MFAMethod = "SMS" | "EMAIL";

/* ---------- INTERFACES ---------- */
interface IRegistrationRequirements {
  requiredFields: string[];
  optionalFields: string[];
  verificationRequired: boolean;
  termsAcceptanceRequired: boolean;
}

interface ITraditionalFlow {
  enabled: boolean;
  registration: IRegistrationRequirements;
  loginMethods: LoginMethod[];
  allowGuestMode: boolean;
  accountActivationFlow: "EMAIL" | "PHONE" | "ADMIN" | "IMMEDIATE";
}

interface ISSOProvider {
  name: string;
  type: "OAUTH2" | "SAML" | "OIDC";
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  enabled: boolean;
  testMode: boolean;
  autoCreateAccount: boolean;
  userInfoMapping: {
    email: string;
    firstName: string;
    lastName: string;
    profilePicture?: string;
    phone?: string;
  };
  additionalParams?: Record<string, any>;
}

interface ISSOFlow {
  enabled: boolean;
  providers: ISSOProvider[];
  requireProfileCompletion: boolean;
  profileCompletionFields: string[];
}

interface IMFATrustedDevices {
  enabled: boolean;
  defaultExpirationDays: number;
  maxTrustedDevices: number;
  requireReauth: boolean;
}

interface IMFA {
  enabled: boolean;
  mandatory: boolean;
  methods: MFAMethod[];
  requireProfileCompletion: boolean;
  profileCompletionFields: string[];
  trustedDevices: IMFATrustedDevices;
}

interface IPasswordPolicy {
  minLength: number;
  maxLength?: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  forbiddenPasswords: string[];
  preventReuse: number;
  passwordExpiryDays: number;
  strengthMeter: boolean;
  customRegexPattern?: string;
}

interface ISessionManagement {
  maxSessionDurationHours: number;
  idleTimeoutMinutes: number;
  revocationOnPasswordChange: boolean;
  deviceRecognition: boolean;
  concurrentSessionLimit: number;
  rememberMe: {
    enabled: boolean;
    durationDays: number;
  };
  securitySettings: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: "strict" | "lax" | "none";
  };
}

export interface IAuthSettings {
  allowGuestMode: boolean;
  traditionalFlow: ITraditionalFlow;
  ssoFlow: ISSOFlow;
  mfa: IMFA;
  passwordPolicy: IPasswordPolicy;
  sessionManagement: ISessionManagement;
  emailSettings: {
    provider: string;
    fromAddress: string;
    templates: Record<string, string>;
  };
  smsSettings: {
    provider: string;
    fromNumber?: string;
    templates: Record<string, string>;
  };
}

/* ---------- MONGOOSE SCHEMAS ---------- */

// Traditional Flow
const RegistrationRequirementsSchema = new Schema({
  requiredFields: { type: [String], default: ["email", "password", "firstName", "lastName"] },
  optionalFields: { type: [String], default: ["phone", "dateOfBirth"] },
  verificationRequired: { type: Boolean, default: true },
  termsAcceptanceRequired: { type: Boolean, default: true },
});

const TraditionalFlowSchema = new Schema({
  enabled: { type: Boolean, default: true },
  registration: { type: RegistrationRequirementsSchema, required: true },
  loginMethods: { type: [String], enum: ["EMAIL", "PHONE", "USERNAME"], default: ["EMAIL"] },
  allowGuestMode: { type: Boolean, default: false },
  accountActivationFlow: { type: String, enum: ["EMAIL", "PHONE", "ADMIN", "IMMEDIATE"], default: "EMAIL" },
});

// SSO Flow
const SSOProviderSchema = new Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ["OAUTH2", "SAML", "OIDC"], required: true },
  clientId: { type: String, required: true },
  clientSecret: { type: String, required: true },
  redirectUri: { type: String, required: true },
  scopes: { type: [String], default: ["openid", "profile", "email"] },
  enabled: { type: Boolean, default: true },
  testMode: { type: Boolean, default: false },
  autoCreateAccount: { type: Boolean, default: true },
  userInfoMapping: {
    email: { type: String, default: "email" },
    firstName: { type: String, default: "given_name" },
    lastName: { type: String, default: "family_name" },
    profilePicture: { type: String },
    phone: { type: String },
  },
  additionalParams: { type: Schema.Types.Mixed, default: {} },
});

const SSOFlowSchema = new Schema({
  enabled: { type: Boolean, default: false },
  providers: { type: [SSOProviderSchema], default: [] },
  requireProfileCompletion: { type: Boolean, default: false },
  profileCompletionFields: { type: [String], default: [] },
});

// MFA Flow
const MFATrustedDevicesSchema = new Schema({
  enabled: { type: Boolean, default: true },
  defaultExpirationDays: { type: Number, default: 30 },
  maxTrustedDevices: { type: Number, default: 5 },
  requireReauth: { type: Boolean, default: false },
});

const MFASchema = new Schema({
  enabled: { type: Boolean, default: true },
  mandatory: { type: Boolean, default: false },
  methods: { type: [String], enum: ["SMS", "EMAIL"], default: ["SMS"] },
  requireProfileCompletion: { type: Boolean, default: false },
  profileCompletionFields: { type: [String], default: [] },
  trustedDevices: { type: MFATrustedDevicesSchema, required: true },
});

// Password Policy
const PasswordPolicySchema = new Schema({
  minLength: { type: Number, default: 8 },
  maxLength: { type: Number },
  requireUppercase: { type: Boolean, default: true },
  requireLowercase: { type: Boolean, default: true },
  requireNumbers: { type: Boolean, default: true },
  requireSymbols: { type: Boolean, default: false },
  forbiddenPasswords: { type: [String], default: [] },
  preventReuse: { type: Number, default: 5 },
  passwordExpiryDays: { type: Number, default: 0 },
  strengthMeter: { type: Boolean, default: true },
  customRegexPattern: { type: String },
});

// Session Management
const SessionManagementSchema = new Schema({
  maxSessionDurationHours: { type: Number, default: 24 },
  idleTimeoutMinutes: { type: Number, default: 30 },
  revocationOnPasswordChange: { type: Boolean, default: true },
  deviceRecognition: { type: Boolean, default: true },
  concurrentSessionLimit: { type: Number, default: 5 },
  rememberMe: {
    enabled: { type: Boolean, default: true },
    durationDays: { type: Number, default: 30 },
  },
  securitySettings: {
    httpOnly: { type: Boolean, default: true },
    secure: { type: Boolean, default: true },
    sameSite: { type: String, enum: ["strict", "lax", "none"], default: "lax" },
  },
});

// Auth Settings Schema
const AuthSettingsSchema = new Schema<IAuthSettings>({
  allowGuestMode: { type: Boolean, default: false },
  traditionalFlow: { type: TraditionalFlowSchema, required: true },
  ssoFlow: { type: SSOFlowSchema, required: true },
  mfa: { type: MFASchema, required: true },
  passwordPolicy: { type: PasswordPolicySchema, required: true },
  sessionManagement: { type: SessionManagementSchema, required: true },
  emailSettings: {
    provider: { type: String, default: "smtp" },
    fromAddress: { type: String, default: "noreply@example.com" },
    templates: { type: Schema.Types.Mixed, default: {} },
  },
  smsSettings: {
    provider: { type: String, default: "twilio" },
    fromNumber: { type: String },
    templates: { type: Schema.Types.Mixed, default: {} },
  },
});

/* ---------- PROJECT SETTINGS ---------- */
export interface IProjectSettings extends Document {
  category: "AUTH";
  settings: IAuthSettings;
  updatedAt: Date;
}

const ProjectSettingsSchema = new Schema<IProjectSettings>(
  {
    category: { type: String, enum: ["AUTH"], required: true },
    settings: { type: AuthSettingsSchema, required: true },
    updatedAt: { type: Date, default: Date.now },
  },
  { discriminatorKey: "category" }
);

ProjectSettingsSchema.index({ category: 1 }, { unique: true });

ProjectSettingsSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

const ProjectSettingsModel = mongoose.model<IProjectSettings>(
  "ProjectSettings",
  ProjectSettingsSchema
);

export default ProjectSettingsModel;