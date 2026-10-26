// Test support (not part of the package API): in-memory OpenTelemetry providers registered as the
// global ones, so tests can inspect the spans and metrics a component records.
import { metrics, trace } from '@opentelemetry/api';
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor, type ReadableSpan } from '@opentelemetry/sdk-trace-base';
import { AggregationTemporality, InMemoryMetricExporter, MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';

export function useSpanRecorder(): { spans(): ReadableSpan[]; dispose(): Promise<void> } {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
  trace.disable();
  trace.setGlobalTracerProvider(provider);
  return {
    spans: () => exporter.getFinishedSpans(),
    dispose: async () => {
      trace.disable();
      await provider.shutdown();
    },
  };
}

export function useMetricRecorder(): { collect(): Promise<Map<string, number>>; dispose(): Promise<void> } {
  const exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
  const reader = new PeriodicExportingMetricReader({ exporter, exportIntervalMillis: 60_000 });
  const provider = new MeterProvider({ readers: [reader] });
  metrics.disable();
  metrics.setGlobalMeterProvider(provider);
  return {
    // Every data point's value, keyed "scope|metric|attr=value,...".
    collect: async () => {
      const { resourceMetrics } = await reader.collect();
      const points = new Map<string, number>();
      for (const scope of resourceMetrics.scopeMetrics) {
        for (const metric of scope.metrics) {
          for (const point of metric.dataPoints) {
            // Code-unit order, not localeCompare: the key must be the same on every machine.
            const attributes = Object.entries(point.attributes)
              .map(([k, v]) => `${k}=${String(v)}`)
              .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
              .join(',');
            points.set(`${scope.scope.name}|${metric.descriptor.name}|${metric.descriptor.unit}|${attributes}`, point.value as number);
          }
        }
      }
      return points;
    },
    dispose: async () => {
      metrics.disable();
      await provider.shutdown();
    },
  };
}
