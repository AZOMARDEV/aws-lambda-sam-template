import { SQS } from 'aws-sdk';

export class SQSService {
    private sqsClient: SQS;

    constructor() {
        this.sqsClient = new SQS({ apiVersion: '2012-11-05' });
    }

    /**
     * Send a single message to SQS queue
     */
    async sendMessage(queueUrl: string, messageBody: any, options?: {
        delaySeconds?: number;
        messageGroupId?: string;
        messageDeduplicationId?: string;
        messageAttributes?: Record<string, any>;
    }): Promise<SQS.SendMessageResult> {
        try {
            const params: SQS.SendMessageRequest = {
                QueueUrl: queueUrl,
                MessageBody: typeof messageBody === 'string' ? messageBody : JSON.stringify(messageBody),
            };

            // Add optional parameters
            if (options?.delaySeconds) {
                params.DelaySeconds = options.delaySeconds;
            }
            if (options?.messageGroupId) {
                params.MessageGroupId = options.messageGroupId;
            }
            if (options?.messageDeduplicationId) {
                params.MessageDeduplicationId = options.messageDeduplicationId;
            }
            if (options?.messageAttributes) {
                params.MessageAttributes = this.formatMessageAttributes(options.messageAttributes);
            }

            const result = await this.sqsClient.sendMessage(params).promise();

            console.log('Message sent successfully:', {
                messageId: result.MessageId,
                queueUrl: queueUrl
            });

            return result;
        } catch (error) {
            console.error('SQS send message failed:', error);
            throw error;
        }
    }

    /**
     * Send multiple messages to SQS queue (batch operation)
     */
    async sendMessageBatch(queueUrl: string, messages: Array<{
        id: string;
        messageBody: any;
        delaySeconds?: number;
        messageGroupId?: string;
        messageDeduplicationId?: string;
        messageAttributes?: Record<string, any>;
    }>): Promise<SQS.SendMessageBatchResult> {
        try {
            const entries: SQS.SendMessageBatchRequestEntryList = messages.map(msg => {
                const entry: SQS.SendMessageBatchRequestEntry = {
                    Id: msg.id,
                    MessageBody: typeof msg.messageBody === 'string' ? msg.messageBody : JSON.stringify(msg.messageBody),
                };

                if (msg.delaySeconds) entry.DelaySeconds = msg.delaySeconds;
                if (msg.messageGroupId) entry.MessageGroupId = msg.messageGroupId;
                if (msg.messageDeduplicationId) entry.MessageDeduplicationId = msg.messageDeduplicationId;
                if (msg.messageAttributes) {
                    entry.MessageAttributes = this.formatMessageAttributes(msg.messageAttributes);
                }

                return entry;
            });

            const result = await this.sqsClient.sendMessageBatch({
                QueueUrl: queueUrl,
                Entries: entries
            }).promise();

            console.log('Batch messages sent successfully:', {
                successful: result.Successful?.length || 0,
                failed: result.Failed?.length || 0,
                queueUrl: queueUrl
            });

            return result;
        } catch (error) {
            console.error('SQS send message batch failed:', error);
            throw error;
        }
    }

    /**
     * Receive messages from SQS queue
     */
    async receiveMessages(queueUrl: string, options?: {
        maxNumberOfMessages?: number;
        waitTimeSeconds?: number;
        visibilityTimeoutSeconds?: number;
        messageAttributeNames?: string[];
    }): Promise<SQS.Message[]> {
        try {
            const params: SQS.ReceiveMessageRequest = {
                QueueUrl: queueUrl,
                MaxNumberOfMessages: options?.maxNumberOfMessages || 1,
                WaitTimeSeconds: options?.waitTimeSeconds || 0,
                MessageAttributeNames: options?.messageAttributeNames || ['All']
            };

            if (options?.visibilityTimeoutSeconds) {
                params.VisibilityTimeout = options.visibilityTimeoutSeconds;
            }

            const result = await this.sqsClient.receiveMessage(params).promise();
            return result.Messages || [];
        } catch (error) {
            console.error('SQS receive messages failed:', error);
            throw error;
        }
    }

    /**
     * Delete a message from SQS queue
     */
    async deleteMessage(queueUrl: string, receiptHandle: string): Promise<void> {
        try {
            await this.sqsClient.deleteMessage({
                QueueUrl: queueUrl,
                ReceiptHandle: receiptHandle
            }).promise();

            console.log('Message deleted successfully');
        } catch (error) {
            console.error('SQS delete message failed:', error);
            throw error;
        }
    }

    /**
     * Delete multiple messages from SQS queue (batch operation)
     */
    async deleteMessageBatch(queueUrl: string, messages: Array<{
        id: string;
        receiptHandle: string;
    }>): Promise<SQS.DeleteMessageBatchResult> {
        try {
            const entries: SQS.DeleteMessageBatchRequestEntryList = messages.map(msg => ({
                Id: msg.id,
                ReceiptHandle: msg.receiptHandle
            }));

            const result = await this.sqsClient.deleteMessageBatch({
                QueueUrl: queueUrl,
                Entries: entries
            }).promise();

            console.log('Batch messages deleted successfully:', {
                successful: result.Successful?.length || 0,
                failed: result.Failed?.length || 0
            });

            return result;
        } catch (error) {
            console.error('SQS delete message batch failed:', error);
            throw error;
        }
    }

    /**
     * Get queue attributes
     */
    async getQueueAttributes(queueUrl: string, attributeNames?: string[]): Promise<SQS.GetQueueAttributesResult> {
        try {
            return await this.sqsClient.getQueueAttributes({
                QueueUrl: queueUrl,
                AttributeNames: attributeNames || ['All']
            }).promise();
        } catch (error) {
            console.error('SQS get queue attributes failed:', error);
            throw error;
        }
    }

    /**
     * Format message attributes for SQS
     */
    private formatMessageAttributes(attributes: Record<string, any>): SQS.MessageBodyAttributeMap {
        const formatted: SQS.MessageBodyAttributeMap = {};

        for (const [key, value] of Object.entries(attributes)) {
            if (typeof value === 'string') {
                formatted[key] = {
                    DataType: 'String',
                    StringValue: value
                };
            } else if (typeof value === 'number') {
                formatted[key] = {
                    DataType: 'Number',
                    StringValue: value.toString()
                };
            } else if (typeof value === 'boolean') {
                formatted[key] = {
                    DataType: 'String',
                    StringValue: value.toString()
                };
            } else {
                formatted[key] = {
                    DataType: 'String',
                    StringValue: JSON.stringify(value)
                };
            }
        }

        return formatted;
    }
}