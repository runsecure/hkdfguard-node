import type { Counter } from '@opentelemetry/api';
import { MetricNames } from './names.js';
import { HkdfGuardTelemetry } from './telemetry.js';

/**
 * Cache component instruments, on the Cache meter. The counter is resolved from the current global
 * meter provider on each access; providers cache instruments by name, so repeated access returns
 * the same instrument.
 */
export const CacheMetrics = {
  /**
   * Counts every protected-cache add/addOrUpdate, tagged with AttributeNames.operationName (which
   * cache span ran) and AttributeNames.result ("success" or "error").
   */
  get operations(): Counter {
    return HkdfGuardTelemetry.cache.meter.createCounter(MetricNames.cacheOperations, {
      unit: '{operation}',
      description: 'Number of ProtectedCache operations, tagged by operation and result.',
    });
  },
};
