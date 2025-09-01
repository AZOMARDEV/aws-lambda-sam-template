interface LogContext {
    [key: string]: any;
}

export interface Logger {
    info: (message: string, context?: LogContext) => void;
    error: (message: string, context?: LogContext) => void;
    warn: (message: string, context?: LogContext) => void;
    debug: (message: string, context?: LogContext) => void;
    appendPersistentKeys: (keys: LogContext) => void;
    logPerformance: (operation: string, duration: number) => void;
    logBusinessEvent: (event: string, data: any) => void;
}

/**
 * Utility class for handling log timestamps and formatting
 */
class LogTimestampHandler {
    /**
     * Get current timestamp in ISO format
     */
    static getCurrentTimestamp(): string {
        return new Date().toISOString();
    }

    /**
     * Get timestamp with timezone offset
     */
    static getCurrentTimestampWithOffset(): string {
        const now = new Date();
        const offset = now.getTimezoneOffset();
        const offsetHours = Math.floor(Math.abs(offset) / 60);
        const offsetMinutes = Math.abs(offset) % 60;
        const offsetSign = offset <= 0 ? '+' : '-';
        
        return `${now.toISOString().slice(0, -1)}${offsetSign}${offsetHours.toString().padStart(2, '0')}:${offsetMinutes.toString().padStart(2, '0')}`;
    }

    /**
     * Format duration in milliseconds to human readable format
     */
    static formatDuration(durationMs: number): string {
        if (durationMs < 1000) {
            return `${durationMs}ms`;
        } else if (durationMs < 60000) {
            return `${(durationMs / 1000).toFixed(2)}s`;
        } else {
            const minutes = Math.floor(durationMs / 60000);
            const seconds = ((durationMs % 60000) / 1000).toFixed(2);
            return `${minutes}m ${seconds}s`;
        }
    }

    /**
     * Create a performance timer
     */
    static createTimer(): () => number {
        const startTime = Date.now();
        return () => Date.now() - startTime;
    }
}

/**
 * Enhanced logger with automatic timestamp handling
 */
export const createLogger = (serviceName: string, requestId: string): Logger => {
    const persistentContext: LogContext = {
        service: serviceName,
        requestId: requestId,
        sessionStartTime: LogTimestampHandler.getCurrentTimestamp()
    };

    const formatLog = (level: string, message: string, context?: LogContext) => {
        return JSON.stringify({
            level,
            message,
            timestamp: LogTimestampHandler.getCurrentTimestamp(),
            ...persistentContext,
            ...context
        });
    };

    const logger: Logger = {
        info: (message: string, context?: LogContext) => {
            console.log(formatLog('INFO', message, context));
        },

        error: (message: string, context?: LogContext) => {
            console.error(formatLog('ERROR', message, context));
        },

        warn: (message: string, context?: LogContext) => {
            console.warn(formatLog('WARN', message, context));
        },

        debug: (message: string, context?: LogContext) => {
            console.debug(formatLog('DEBUG', message, context));
        },

        appendPersistentKeys: (keys: LogContext) => {
            Object.assign(persistentContext, keys);
        },

        logPerformance: (operation: string, duration: number) => {
            console.log(formatLog('PERFORMANCE', `Operation ${operation} completed`, {
                operation,
                duration,
                durationFormatted: LogTimestampHandler.formatDuration(duration),
                performanceMetric: true
            }));
        },

        logBusinessEvent: (event: string, data: any) => {
            console.log(formatLog('BUSINESS_EVENT', `Business event: ${event}`, {
                event,
                eventData: data,
                businessEvent: true
            }));
        }
    };

    return logger;
};

/**
 * Performance monitoring utility for timing operations
 */
export class PerformanceMonitor {
    private timers: Map<string, number> = new Map();
    private logger: Logger;

    constructor(logger: Logger) {
        this.logger = logger;
    }

    /**
     * Start timing an operation
     */
    startTimer(operationName: string): void {
        this.timers.set(operationName, Date.now());
    }

    /**
     * End timing an operation and log the result
     */
    endTimer(operationName: string): number {
        const startTime = this.timers.get(operationName);
        if (!startTime) {
            this.logger.warn(`Timer not found for operation: ${operationName}`);
            return 0;
        }

        const duration = Date.now() - startTime;
        this.logger.logPerformance(operationName, duration);
        this.timers.delete(operationName);
        return duration;
    }

    /**
     * Get duration without logging
     */
    getDuration(operationName: string): number {
        const startTime = this.timers.get(operationName);
        if (!startTime) {
            return 0;
        }
        return Date.now() - startTime;
    }

    /**
     * Clear all timers
     */
    clearAll(): void {
        this.timers.clear();
    }
}

/**
 * Factory function to create logger with performance monitor
 */
export const createLoggerWithMonitor = (serviceName: string, requestId: string) => {
    const logger = createLogger(serviceName, requestId);
    const performanceMonitor = new PerformanceMonitor(logger);
    
    return {
        logger,
        performanceMonitor,
        // Convenience method for timed operations
        timeOperation: async <T>(operationName: string, operation: () => Promise<T>): Promise<T> => {
            performanceMonitor.startTimer(operationName);
            try {
                const result = await operation();
                performanceMonitor.endTimer(operationName);
                return result;
            } catch (error) {
                performanceMonitor.endTimer(operationName);
                throw error;
            }
        }
    };
};

// Export timestamp handler for external use
export { LogTimestampHandler };