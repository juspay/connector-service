/**
 * Production-grade logger for payment SDK
 * Features: structured logging, PII redaction, environment configuration,
 * child loggers, and multiple output formats
 */

// Log level definitions with priority (higher = more verbose)
type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

// ANSI color codes for terminal output
const COLORS = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

// Log level color mapping
const LEVEL_COLORS: Record<string, string> = {
  error: COLORS.red,
  warn: COLORS.yellow,
  info: COLORS.green,
  debug: COLORS.blue,
};

// Sensitive field patterns for automatic redaction (payment-specific)
const SENSITIVE_PATTERNS = [
  // Card data
  /cardNumber|card_num|pan|cardPan/i,
  /cardCvc|cvv|cvc|securityCode/i,
  /cardExpMonth|exp_month|expiryMonth/i,
  /cardExpYear|exp_year|expiryYear/i,
  // Authentication
  /clientSecret|client_secret|apiKey|api_key|apiSecret|api_secret/i,
  /accessToken|access_token|refreshToken|refresh_token|token|bearer/i,
  /password|secret|privateKey|private_key/i,
  // Identity
  /ssn|socialSecurity|taxId|ein/i,
];

/**
 * Check if a key should be redacted
 */
function shouldRedact(key: string): boolean {
  return SENSITIVE_PATTERNS.some(pattern => pattern.test(key));
}

/**
 * Redact sensitive values from objects
 */
function redactSensitiveData<T>(data: T): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Redact card numbers (common patterns)
    return data.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[REDACTED_CARD]') as unknown as T;
  }

  if (typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => redactSensitiveData(item)) as unknown as T;
  }

  const redacted: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (shouldRedact(key)) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactSensitiveData(value);
    } else {
      redacted[key] = value;
    }
  }

  return redacted as T;
}

/**
 * Safely serialize data to JSON with circular reference handling
 */
function safeStringify(obj: unknown): string {
  const seen = new Set<unknown>();
  return JSON.stringify(obj, (key, value) => {
    // Redact sensitive fields during serialization
    if (shouldRedact(key)) {
      return '[REDACTED]';
    }

    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'object') {
      if (seen.has(value)) {
        return '[Circular]';
      }
      seen.add(value);
    }

    // Handle Error objects
    if (value instanceof Error) {
      return {
        name: value.name,
        message: value.message,
        stack: value.stack,
      };
    }

    return value;
  });
}

/**
 * Format timestamp as ISO8601
 */
function formatTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Check if running in a TTY (supports colors)
 */
function supportsColor(): boolean {
  return typeof process !== 'undefined' && process.stdout?.isTTY === true;
}

/**
 * Logger configuration from environment
 */
interface LoggerConfig {
  level: LogLevel;
  format: 'json' | 'pretty';
  enableColors: boolean;
  context?: Record<string, unknown>;
}

/**
 * Structured log entry
 */
interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  context?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  [key: string]: unknown;
}

/**
 * Production-grade logger class
 */
class Logger {
  private config: LoggerConfig;

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = {
      level: this.getEnvLevel(),
      format: this.getEnvFormat(),
      enableColors: config.enableColors ?? (supportsColor() && process.env.LOG_COLOR !== 'false'),
      context: config.context,
    };
  }

  /**
   * Get log level from environment
   */
  private getEnvLevel(): LogLevel {
    const envLevel = process.env.LOG_LEVEL?.toLowerCase() as LogLevel;
    if (envLevel && envLevel in LEVEL_PRIORITY) {
      return envLevel;
    }
    return 'info';
  }

  /**
   * Get output format from environment
   */
  private getEnvFormat(): 'json' | 'pretty' {
    const envFormat = process.env.LOG_FORMAT?.toLowerCase();
    if (envFormat === 'json') return 'json';
    if (envFormat === 'pretty') return 'pretty';
    // Default: pretty for development, json for production
    return process.env.NODE_ENV === 'production' ? 'json' : 'pretty';
  }

  /**
   * Check if message should be logged at current level
   */
  private shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] <= LEVEL_PRIORITY[this.config.level];
  }

  /**
   * Format log entry as pretty string for development
   */
  private formatPretty(entry: LogEntry): string {
    const color = this.config.enableColors ? LEVEL_COLORS[entry.level] || '' : '';
    const reset = this.config.enableColors ? COLORS.reset : '';
    const dim = this.config.enableColors ? COLORS.dim : '';

    let output = `${dim}[${entry.timestamp}]${reset} ${color}[${entry.level.toUpperCase()}]${reset} ${entry.message}`;

    // Add context if present
    if (entry.context && Object.keys(entry.context).length > 0) {
      const contextStr = Object.entries(entry.context)
        .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
        .join(' ');
      output += ` ${dim}{${contextStr}}${reset}`;
    }

    // Add error details if present
    if (entry.error) {
      output += `\n  ${color}↳ ${entry.error.name}:${reset} ${entry.error.message}`;
      if (entry.error.stack && this.config.level === 'debug') {
        const stackLines = entry.error.stack.split('\n').slice(1, 4).join('\n    ');
        output += `\n  ${dim}Stack:${reset}\n    ${stackLines}`;
      }
    }

    return output;
  }

  /**
   * Format log entry as JSON for production
   */
  private formatJson(entry: LogEntry): string {
    // Redact sensitive data before output
    const sanitized = redactSensitiveData(entry);
    return safeStringify(sanitized);
  }

  /**
   * Create a log entry and output it
   */
  private log(
    level: LogLevel,
    message: string,
    error?: Error,
    meta?: Record<string, unknown>
  ): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      timestamp: formatTimestamp(),
      level,
      message,
    };

    // Add context from logger instance and call metadata
    const context = {
      ...this.config.context,
      ...meta,
    };

    if (Object.keys(context).length > 0) {
      entry.context = context;
    }

    // Add error information if provided
    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    }

    // Format and output
    const output = this.config.format === 'json'
      ? this.formatJson(entry)
      : this.formatPretty(entry);

    // Output to appropriate stream
    if (level === 'error') {
      console.error(output);
    } else if (level === 'warn') {
      console.warn(output);
    } else {
      console.log(output);
    }
  }

  /**
   * Set log level at runtime
   */
  set level(level: LogLevel) {
    if (level in LEVEL_PRIORITY) {
      this.config.level = level;
    }
  }

  /**
   * Get current log level
   */
  get level(): LogLevel {
    return this.config.level;
  }

  /**
   * Log debug message (verbose debugging information)
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    this.log('debug', message, undefined, meta);
  }

  /**
   * Log info message (general information)
   */
  info(message: string, meta?: Record<string, unknown>): void {
    this.log('info', message, undefined, meta);
  }

  /**
   * Log warning message (potential issues)
   */
  warn(message: string, meta?: Record<string, unknown>): void {
    this.log('warn', message, undefined, meta);
  }

  /**
   * Log error message (errors, optionally with Error object)
   */
  error(message: string, error?: Error | unknown, meta?: Record<string, unknown>): void {
    const err = error instanceof Error ? error : undefined;
    this.log('error', message, err, meta);
  }

  /**
   * Create a child logger with additional context
   */
  child(context: Record<string, unknown>): Logger {
    return new Logger({
      ...this.config,
      context: {
        ...this.config.context,
        ...context,
      },
    });
  }
}

// Export singleton instance
export const logger = new Logger();

/**
 * Enable or disable verbose logging (backward compatibility)
 */
export function setVerbose(verbose: boolean): void {
  logger.level = verbose ? 'debug' : 'info';
}

/**
 * Create a new logger instance with custom configuration
 */
export function createLogger(config: Partial<LoggerConfig>): Logger {
  return new Logger(config);
}