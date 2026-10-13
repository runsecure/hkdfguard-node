/**
 * The single place every HkdfGuard component's OpenTelemetry tracing, metrics, sensitive-logging
 * toggle, and structured-log helpers live - the Node port of the .NET HkdfGuard.Diagnostics
 * library. Span, event, metric, and attribute names are identical across ports.
 */
export { AttributeNames, EventNames, MetricNames, Results, SpanNames } from './names.js';
export { ComponentTelemetry, HkdfGuardTelemetry, recordException } from './telemetry.js';
export { CacheMetrics } from './metrics.js';
export { HkdfGuardLog, LogKeys, type Logger } from './logging.js';
