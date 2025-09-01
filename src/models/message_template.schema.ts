import { Schema, model, Document, Types } from 'mongoose';

// Interfaces
export interface ITemplateVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date' | 'url';
  required: boolean;
  defaultValue?: any;
  validation?: {
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    enum?: string[];
  };
}

export interface IEmailChannel {
  enabled: boolean;
  templateUrl?: string;
  htmlContent?: string;
  textContent?: string;
  subject: string;
  fromName?: string;
  fromEmail?: string;
  replyTo?: string;
  variables: Record<string, string>;
  attachments?: {
    name: string;
    url: string;
    type: string;
  }[];
}

export interface ISmsChannel {
  enabled: boolean;
  message: string;
  sender?: string;
  variables: Record<string, string>;
  encoding: 'GSM7' | 'UCS2';
  maxLength: number;
}

export interface IWhatsappChannel {
  enabled: boolean;
  templateId?: string;
  templateName?: string;
  message?: string;
  mediaUrl?: string;
  mediaType?: 'image' | 'video' | 'document' | 'audio';
  variables: Record<string, string>;
  components?: {
    type: 'header' | 'body' | 'footer' | 'button';
    parameters?: {
      type: 'text' | 'currency' | 'date_time' | 'image' | 'document' | 'video';
      text?: string;
      currency?: {
        fallback_value: string;
        code: string;
        amount_1000: number;
      };
      date_time?: {
        fallback_value: string;
      };
      image?: { link: string };
      document?: { link: string; filename: string };
      video?: { link: string };
    }[];
  }[];
}

export interface IPushChannel {
  enabled: boolean;
  title: string;
  body: string;
  icon?: string;
  image?: string;
  sound?: string;
  badge?: number;
  clickAction?: string;
  variables: Record<string, string>;
  customData?: Record<string, any>;
}

export interface IChannels {
  email?: IEmailChannel;
  sms?: ISmsChannel;
  whatsapp?: IWhatsappChannel;
  push?: IPushChannel;
}

export interface ILocalization {
  defaultLanguage: string;
  translations: Record<string, {
    email?: {
      subject: string;
      htmlContent?: string;
      textContent?: string;
    };
    sms?: {
      message: string;
    };
    whatsapp?: {
      message: string;
    };
    push?: {
      title: string;
      body: string;
    };
  }>;
}

export interface ITesting {
  testMode: boolean;
  testRecipients: {
    email?: string[];
    phone?: string[];
    pushTokens?: string[];
  };
  splitTesting?: {
    enabled: boolean;
    variants: {
      name: string;
      weight: number;
      channels: IChannels;
    }[];
  };
}

export interface IAnalytics {
  trackOpens: boolean;
  trackClicks: boolean;
  trackConversions: boolean;
  customEvents?: string[];
  retentionPeriod: number; // days
}

export interface IMessageTemplate extends Document {
  appId: Types.ObjectId;
  name: string;
  displayName: string;
  description?: string;
  category: 'auth' | 'notification' | 'marketing' | 'transactional' | 'system';
  type: 'welcome' | 'verification' | 'password_reset' | 'mfa' | 'notification' | 'promotional' | 'reminder' | 'alert';
  channels: IChannels;
  variables: ITemplateVariable[];
  localization?: ILocalization;
  testing: ITesting;
  analytics: IAnalytics;
  scheduling?: {
    allowScheduling: boolean;
    timezone?: string;
    deliveryWindow?: {
      start: string; // HH:mm format
      end: string; // HH:mm format
      days: number[]; // 0-6, Sunday = 0
    };
    frequency?: {
      type: 'once' | 'daily' | 'weekly' | 'monthly';
      interval?: number;
      endDate?: Date;
    };
  };
  compliance: {
    requiresConsent: boolean;
    consentType?: 'marketing' | 'transactional';
    includeUnsubscribe: boolean;
    gdprCompliant: boolean;
    dataRetention: number; // days
  };
  version: {
    major: number;
    minor: number;
    patch: number;
  };
  status: 'draft' | 'active' | 'archived';
  approvalStatus: 'pending' | 'approved' | 'rejected';
  approvedBy?: Types.ObjectId;
  approvedAt?: Date;
  rejectionReason?: string;
  usage: {
    totalSent: number;
    lastSent?: Date;
    avgDeliveryTime: number; // milliseconds
    deliveryRate: number; // percentage
    openRate: number; // percentage (email)
    clickRate: number; // percentage (email)
  };
  isActive: boolean;
  createdBy: Types.ObjectId;
  updatedBy: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

// Schemas
const TemplateVariableSchema = new Schema<ITemplateVariable>({
  name: { type: String, required: true },
  type: {
    type: String,
    enum: ['string', 'number', 'boolean', 'date', 'url'],
    default: 'string'
  },
  required: { type: Boolean, default: false },
  defaultValue: Schema.Types.Mixed,
  validation: {
    minLength: Number,
    maxLength: Number,
    pattern: String,
    enum: [String]
  }
}, { _id: false });

const AttachmentSchema = new Schema({
  name: { type: String, required: true },
  url: { type: String, required: true },
  type: { type: String, required: true }
}, { _id: false });

const EmailChannelSchema = new Schema<IEmailChannel>({
  enabled: { type: Boolean, default: false },
  templateUrl: String,
  htmlContent: String,
  textContent: String,
  subject: { type: String, required: true },
  fromName: String,
  fromEmail: String,
  replyTo: String,
  variables: { type: Schema.Types.Mixed, default: {} },
  attachments: [AttachmentSchema]
}, { _id: false });

const SmsChannelSchema = new Schema<ISmsChannel>({
  enabled: { type: Boolean, default: false },
  message: { type: String, required: true },
  sender: String,
  variables: { type: Schema.Types.Mixed, default: {} },
  encoding: { type: String, enum: ['GSM7', 'UCS2'], default: 'GSM7' },
  maxLength: { type: Number, default: 160 }
}, { _id: false });

const WhatsappParameterSchema = new Schema({
  type: {
    type: String,
    enum: ['text', 'currency', 'date_time', 'image', 'document', 'video'],
    required: true
  },
  text: String,
  currency: {
    fallback_value: String,
    code: String,
    amount_1000: Number
  },
  date_time: {
    fallback_value: String
  },
  image: { link: String },
  document: { 
    link: String, 
    filename: String 
  },
  video: { link: String }
}, { _id: false });

const WhatsappComponentSchema = new Schema({
  type: {
    type: String,
    enum: ['header', 'body', 'footer', 'button'],
    required: true
  },
  parameters: [WhatsappParameterSchema]
}, { _id: false });

const WhatsappChannelSchema = new Schema<IWhatsappChannel>({
  enabled: { type: Boolean, default: false },
  templateId: String,
  templateName: String,
  message: String,
  mediaUrl: String,
  mediaType: {
    type: String,
    enum: ['image', 'video', 'document', 'audio']
  },
  variables: { type: Schema.Types.Mixed, default: {} },
  components: [WhatsappComponentSchema]
}, { _id: false });

const PushChannelSchema = new Schema<IPushChannel>({
  enabled: { type: Boolean, default: false },
  title: { type: String, required: true },
  body: { type: String, required: true },
  icon: String,
  image: String,
  sound: String,
  badge: Number,
  clickAction: String,
  variables: { type: Schema.Types.Mixed, default: {} },
  customData: { type: Schema.Types.Mixed, default: {} }
}, { _id: false });

const ChannelsSchema = new Schema<IChannels>({
  email: EmailChannelSchema,
  sms: SmsChannelSchema,
  whatsapp: WhatsappChannelSchema,
  push: PushChannelSchema
}, { _id: false });

const TranslationChannelSchema = new Schema({
  subject: String,
  htmlContent: String,
  textContent: String,
  message: String,
  title: String,
  body: String
}, { _id: false });

const LocalizationSchema = new Schema<ILocalization>({
  defaultLanguage: { type: String, default: 'en' },
  translations: {
    type: Map,
    of: TranslationChannelSchema,
    default: {}
  }
}, { _id: false });

const TestRecipientsSchema = new Schema({
  email: [String],
  phone: [String],
  pushTokens: [String]
}, { _id: false });

const SplitTestVariantSchema = new Schema({
  name: { type: String, required: true },
  weight: { type: Number, required: true, min: 0, max: 100 },
  channels: ChannelsSchema
}, { _id: false });

const TestingSchema = new Schema<ITesting>({
  testMode: { type: Boolean, default: false },
  testRecipients: TestRecipientsSchema,
  splitTesting: {
    enabled: { type: Boolean, default: false },
    variants: [SplitTestVariantSchema]
  }
}, { _id: false });

const AnalyticsSchema = new Schema<IAnalytics>({
  trackOpens: { type: Boolean, default: true },
  trackClicks: { type: Boolean, default: true },
  trackConversions: { type: Boolean, default: false },
  customEvents: [String],
  retentionPeriod: { type: Number, default: 90 }
}, { _id: false });

const DeliveryWindowSchema = new Schema({
  start: { type: String, required: true }, // HH:mm
  end: { type: String, required: true }, // HH:mm
  days: [{ type: Number, min: 0, max: 6 }] // 0-6, Sunday = 0
}, { _id: false });

const FrequencySchema = new Schema({
  type: {
    type: String,
    enum: ['once', 'daily', 'weekly', 'monthly'],
    default: 'once'
  },
  interval: { type: Number, default: 1 },
  endDate: Date
}, { _id: false });

const SchedulingSchema = new Schema({
  allowScheduling: { type: Boolean, default: false },
  timezone: { type: String, default: 'UTC' },
  deliveryWindow: DeliveryWindowSchema,
  frequency: FrequencySchema
}, { _id: false });

const ComplianceSchema = new Schema({
  requiresConsent: { type: Boolean, default: false },
  consentType: {
    type: String,
    enum: ['marketing', 'transactional']
  },
  includeUnsubscribe: { type: Boolean, default: true },
  gdprCompliant: { type: Boolean, default: true },
  dataRetention: { type: Number, default: 365 }
}, { _id: false });

const VersionSchema = new Schema({
  major: { type: Number, default: 1 },
  minor: { type: Number, default: 0 },
  patch: { type: Number, default: 0 }
}, { _id: false });

const UsageSchema = new Schema({
  totalSent: { type: Number, default: 0 },
  lastSent: Date,
  avgDeliveryTime: { type: Number, default: 0 },
  deliveryRate: { type: Number, default: 0, min: 0, max: 100 },
  openRate: { type: Number, default: 0, min: 0, max: 100 },
  clickRate: { type: Number, default: 0, min: 0, max: 100 }
}, { _id: false });

const MessageTemplateSchema = new Schema<IMessageTemplate>({
  appId: { type: Schema.Types.ObjectId, ref: 'App', required: true },
  name: { 
    type: String, 
    required: true,
    lowercase: true,
    trim: true
  },
  displayName: { type: String, required: true, trim: true },
  description: { type: String, maxlength: 500 },
  category: {
    type: String,
    enum: ['auth', 'notification', 'marketing', 'transactional', 'system'],
    required: true
  },
  type: {
    type: String,
    enum: ['welcome', 'verification', 'password_reset', 'mfa', 'notification', 'promotional', 'reminder', 'alert'],
    required: true
  },
  channels: { type: ChannelsSchema, required: true },
  variables: [TemplateVariableSchema],
  localization: LocalizationSchema,
  testing: { type: TestingSchema, default: () => ({}) },
  analytics: { type: AnalyticsSchema, default: () => ({}) },
  scheduling: SchedulingSchema,
  compliance: { type: ComplianceSchema, default: () => ({}) },
  version: { type: VersionSchema, default: () => ({}) },
  status: {
    type: String,
    enum: ['draft', 'active', 'archived'],
    default: 'draft'
  },
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  approvedBy: { type: Schema.Types.ObjectId, ref: 'Account' },
  approvedAt: Date,
  rejectionReason: String,
  usage: { type: UsageSchema, default: () => ({}) },
  isActive: { type: Boolean, default: true },
  createdBy: { type: Schema.Types.ObjectId, ref: 'Account', required: true },
  updatedBy: { type: Schema.Types.ObjectId, ref: 'Account', required: true }
}, {
  timestamps: true,
  collection: 'message_templates'
});

// Compound indexes
MessageTemplateSchema.index({ appId: 1, name: 1 }, { unique: true });
MessageTemplateSchema.index({ appId: 1, category: 1 });
MessageTemplateSchema.index({ appId: 1, type: 1 });
MessageTemplateSchema.index({ appId: 1, status: 1 });
MessageTemplateSchema.index({ approvalStatus: 1 });
MessageTemplateSchema.index({ isActive: 1 });
MessageTemplateSchema.index({ createdBy: 1 });
MessageTemplateSchema.index({ updatedAt: 1 });

export const MessageTemplate = model<IMessageTemplate>('MessageTemplate', MessageTemplateSchema);