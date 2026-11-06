import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';

/**
 * The start, end and escape sequences that delimit a configuration item, such as `${Name}` - the
 * port of ConfigurationResolver's ConfigurationItemTokenBase. Use the same token for a reader and
 * the resolver given that reader. A token is immutable.
 */
export class ConfigurationItemTokenBase {
  /** The default sequence that marks the start of a configuration item. */
  static readonly DEFAULT_START_SEQUENCE = '${';

  /** The default sequence that marks the end of a configuration item. */
  static readonly DEFAULT_END_SEQUENCE = '}';

  /** The escape sequence of {@link DefaultToken}, so that `$${Name}` is written as the literal text `${Name}`. */
  static readonly DEFAULT_ESCAPE_SEQUENCE = '$';

  /** The sequence that marks the start of a configuration item. */
  readonly startSequence: string;

  /** The sequence that marks the end of a configuration item. */
  readonly endSequence: string;

  /**
   * The sequence that, directly before a start sequence, makes it literal text, or undefined if the
   * token has none. The escape sequence is removed and the start sequence is copied as text, so with
   * the escape sequence `$`, `$${Name}` is written as `${Name}` and `Name` is not a key. Only the
   * start sequence is escaped: the text after it is read as usual, so it can contain other items. An
   * escape sequence anywhere else is ordinary text.
   */
  readonly escapeSequence: string | undefined;

  /**
   * @param startSequence marks the start of a configuration item
   * @param endSequence marks the end of a configuration item
   * @param escapeSequence directly before a start sequence, makes it literal text instead of the
   *   start of an item; undefined, the default, for none
   * @throws TypeError a sequence isn't a string
   * @throws InvalidArgumentError a sequence is empty
   */
  constructor(
    startSequence: string = ConfigurationItemTokenBase.DEFAULT_START_SEQUENCE,
    endSequence: string = ConfigurationItemTokenBase.DEFAULT_END_SEQUENCE,
    escapeSequence?: string,
  ) {
    for (const [name, value] of [['startSequence', startSequence], ['endSequence', endSequence]] as const) {
      if (typeof value !== 'string') throw new TypeError(`${name} must be a string.`);
      if (value.length === 0) throw new InvalidArgumentError(`${name} must not be empty.`);
    }
    if (escapeSequence !== undefined && escapeSequence !== null) {
      if (typeof escapeSequence !== 'string') throw new TypeError('escapeSequence must be a string, or undefined for none.');
      if (escapeSequence.length === 0) throw new InvalidArgumentError('escapeSequence must not be empty; pass undefined for no escape sequence.');
    }
    this.startSequence = startSequence;
    this.endSequence = endSequence;
    this.escapeSequence = escapeSequence ?? undefined;
  }
}

/**
 * A token that uses the default `${` and `}` sequences, with `$` as its escape sequence, so
 * `$${Name}` is written as the literal text `${Name}`.
 */
export class DefaultToken extends ConfigurationItemTokenBase {
  constructor() {
    super(undefined, undefined, ConfigurationItemTokenBase.DEFAULT_ESCAPE_SEQUENCE);
  }
}
