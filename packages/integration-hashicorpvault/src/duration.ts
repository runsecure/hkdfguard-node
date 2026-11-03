// Go's duration syntax - "1h30m", "300ms", "2.5s" - which Vault and its environment variables use.

const NANOS_PER_UNIT = new Map<string, bigint>([
  ['ns', 1n], ['us', 1_000n], ['µs', 1_000n], ['μs', 1_000n], ['ms', 1_000_000n], ['s', 1_000_000_000n], ['m', 60_000_000_000n],
  ['h', 3_600_000_000_000n],
]);
// What a Go duration holds: an int64 of nanoseconds.
const MAX_NANOS = (1n << 63n) - 1n;

/**
 * time.ParseDuration, in milliseconds: an optional sign, then one or more decimal numbers each with
 * a unit (ns, us, µs, ms, s, m, h); "0" alone needs none. Fractions of a millisecond are kept.
 * @throws RangeError `value` isn't a duration, or is longer than Go's
 */
export function parseGoDuration(value: string): number {
  let s = value;
  let negative = false;
  if (s.startsWith('-') || s.startsWith('+')) {
    negative = s.startsWith('-');
    s = s.slice(1);
  }
  if (s === '0') return 0;
  if (s === '') throw new RangeError(`Invalid duration '${value}'.`);

  // Exact: nanoseconds, scaled by 10^9 for the fractions a number may carry.
  const scale = 1_000_000_000n;
  let total = 0n;
  let i = 0;
  const isNumberChar = (c: string) => (c >= '0' && c <= '9') || c === '.';
  while (i < s.length) {
    const start = i;
    while (i < s.length && isNumberChar(s[i]!)) i++;
    const number = s.slice(start, i);
    const [whole = '', fraction = '', extra] = number.split('.');
    if (number === '' || number === '.' || extra !== undefined) throw new RangeError(`Invalid duration '${value}'.`);

    const unitStart = i;
    while (i < s.length && !isNumberChar(s[i]!)) i++;
    const unit = s.slice(unitStart, i);
    if (unit === '') throw new RangeError(`Missing unit in duration '${value}'.`);
    const perUnit = NANOS_PER_UNIT.get(unit);
    if (perUnit === undefined) throw new RangeError(`Unknown unit '${unit}' in duration '${value}'.`);

    const digits = fraction.slice(0, 9).padEnd(9, '0');
    total += (BigInt(whole === '' ? '0' : whole) * scale + BigInt(digits)) * perUnit;
    if (total / scale > MAX_NANOS) throw new RangeError(`The duration '${value}' is too long.`);
  }
  const nanos = total / scale;
  const ms = Number(nanos / 1_000_000n) + Number(nanos % 1_000_000n) / 1_000_000;
  return negative ? -ms : ms;
}

/** Duration.String of `ms` milliseconds: "1h2m3.5s", "5m0s", "1.5ms", "0s". */
export function formatGoDuration(ms: number): string {
  if (ms === 0) return '0s';
  const sign = ms < 0 ? '-' : '';
  const nanos = BigInt(Math.round(Math.abs(ms) * 1_000_000));
  if (nanos < 1_000_000_000n) {
    if (nanos < 1_000n) return `${sign}${nanos}ns`;
    if (nanos < 1_000_000n) return `${sign}${fraction(nanos, 1_000n)}µs`;
    return `${sign}${fraction(nanos, 1_000_000n)}ms`;
  }
  const minutes = nanos / 60_000_000_000n;
  const rest = nanos % 60_000_000_000n;
  const hours = minutes / 60n;
  let text = sign;
  if (hours > 0n) text += `${hours}h`;
  if (minutes > 0n) text += `${minutes % 60n}m`;
  return `${text}${fraction(rest, 1_000_000_000n)}s`;
}

// value / unit, with as many fractional digits as it needs.
function fraction(value: bigint, unit: bigint): string {
  const whole = value / unit;
  const rest = value % unit;
  if (rest === 0n) return `${whole}`;
  const digits = rest.toString().padStart(unit.toString().length - 1, '0').replace(/0+$/, '');
  return `${whole}.${digits}`;
}
