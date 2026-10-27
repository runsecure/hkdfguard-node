export { useMetricRecorder, useSpanRecorder } from './otel.js';
export { capturingLogger, FakeKeyWrapper, TestFormatProvider, type CapturedEntry } from './fakes.js';
export { RecordingFactory, RecordingKey, TestProvider } from './providers.js';
export { keyFileDirectory, linuxKeyFileRoot, untrustedDirectoryChain } from './keyfiles.js';
export { icacls, windowsCurrentUserSid, windowsShortPath } from './windowsaccounts.js';
export { awaitNativeAccess, NATIVE_ACCESS_TIMEOUT_MS, probeNativeAccess } from './nativeaccess.js';
