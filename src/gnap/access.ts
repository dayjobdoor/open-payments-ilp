import * as Result from "effect/Result";
import { parseAmountValue, UINT128_MAX } from "../open-payments/amount";
import type { Amount } from "../open-payments/types";

/** Limits of an outgoing-payment access item, as stored and matched at runtime. */
export interface AccessLimits {
  receiver?: string;
  interval?: string;
  debitAmount?: Amount;
  receiveAmount?: Amount;
}

/**
 * Structural access item used for matching. The wire `AccessItem` of the generated types is stricter at
 * compile time; the matcher only relies on these fields.
 */
export interface AccessMatchItem {
  type: string;
  actions?: string[];
  identifier?: string;
  limits?: AccessLimits;
}

interface AccessIntervalParts {
  years: number;
  months: number;
  weeks: number;
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
}

const SECOND = 1000;

const MINUTE = 60 * SECOND;

const HOUR = 60 * MINUTE;

const DAY = 24 * HOUR;

const WEEK = 7 * DAY;

const ISO_DURATION =
  /^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$/;

function parseAccessIntervalParts(value: string): AccessIntervalParts | null {
  const match = ISO_DURATION.exec(value);

  if (!match || match.slice(1).every((part) => part === undefined)) return null;
  const numbers = match.slice(1).map((part) => (part === undefined ? 0 : Number(part)));

  if (numbers.some((part) => !Number.isFinite(part) || part < 0)) return null;
  const [years, months, weeks, days, hours, minutes, seconds] = numbers;

  if (years === undefined || months === undefined || weeks === undefined || days === undefined) return null;

  return { years, months, weeks, days, hours: hours ?? 0, minutes: minutes ?? 0, seconds: seconds ?? 0 };
}

/** Milliseconds of a duration (years as 365 days, months as 30 days); `null` unless positive and a safe integer. */
function durationMs(parts: AccessIntervalParts): number | null {
  const milliseconds =
    parts.years * 365 * DAY +
    parts.months * 30 * DAY +
    parts.weeks * WEEK +
    parts.days * DAY +
    parts.hours * HOUR +
    parts.minutes * MINUTE +
    parts.seconds * SECOND;

  return Number.isSafeInteger(Math.trunc(milliseconds)) && milliseconds > 0 ? milliseconds : null;
}

function addAccessInterval(date: Date, parts: AccessIntervalParts): Date {
  const next = new Date(date);
  const monthDelta = parts.years * 12 + parts.months;

  if (Number.isInteger(monthDelta) && monthDelta !== 0) {
    const day = next.getUTCDate();

    next.setUTCDate(1);
    next.setUTCFullYear(next.getUTCFullYear(), next.getUTCMonth() + monthDelta, 1);
    const lastDay = new Date(Date.UTC(next.getUTCFullYear(), next.getUTCMonth() + 1, 0)).getUTCDate();

    next.setUTCDate(Math.min(day, lastDay));
  }

  next.setTime(
    next.getTime() +
      parts.weeks * WEEK +
      parts.days * DAY +
      parts.hours * HOUR +
      parts.minutes * MINUTE +
      parts.seconds * SECOND,
  );

  return next;
}

/** `ms` moved by `parts` on the UTC calendar, forward or backward. */
function shift(ms: number, parts: AccessIntervalParts, direction: 1 | -1): number {
  const signed: AccessIntervalParts = {
    years: direction * parts.years,
    months: direction * parts.months,
    weeks: direction * parts.weeks,
    days: direction * parts.days,
    hours: direction * parts.hours,
    minutes: direction * parts.minutes,
    seconds: direction * parts.seconds,
  };

  return addAccessInterval(new Date(ms), signed).getTime();
}

/** A repeating interval (`R[n]/start/duration`, `R[n]/start/end` or `R[n]/duration/end`) with its first window. */
interface RepeatingInterval {
  /** Windows after the first one; `Infinity` for `R` and `R-1`. */
  readonly repetitions: number;
  /** The first window, epoch milliseconds, half-open. */
  readonly start: number;
  readonly end: number;
  /** The duration the windows repeat by; `null` when they are as long as the first (`start/end`). */
  readonly step: AccessIntervalParts | null;
  /** Whether windows follow the first (`start/…`) or precede it (`duration/end`). */
  readonly forward: boolean;
}

const INSTANT = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/;

/** An ISO 8601 date or date-time; without an offset it is UTC (as Rafiki's `Settings.defaultZone`). */
function parseInstant(text: string): number | null {
  if (!INSTANT.test(text)) return null;
  const time = Date.parse(text.includes("T") && !/(Z|[+-]\d{2}:\d{2})$/.test(text) ? `${text}Z` : text);

  return Number.isNaN(time) ? null : time;
}

function parseRepeating(value: string): RepeatingInterval | null {
  const [designator, first, second, ...rest] = value.split("/");
  const repeat = /^R(-1|\d*)$/.exec(designator ?? "");

  if (repeat === null || first === undefined || second === undefined || rest.length > 0) return null;
  const repetitions = repeat[1] === "" || repeat[1] === "-1" ? Infinity : Number(repeat[1]);
  const leading = parseAccessIntervalParts(first);
  const trailing = parseAccessIntervalParts(second);
  const from = parseInstant(first);
  const until = parseInstant(second);

  if (leading !== null && until !== null) {
    const start = shift(until, leading, -1);

    return durationMs(leading) === null || Number.isNaN(start)
      ? null
      : { repetitions, start, end: until, step: leading, forward: false };
  }

  if (from !== null && trailing !== null) {
    const end = shift(from, trailing, 1);

    return durationMs(trailing) === null || Number.isNaN(end)
      ? null
      : { repetitions, start: from, end, step: trailing, forward: true };
  }

  return from !== null && until !== null && until > from
    ? { repetitions, start: from, end: until, step: null, forward: true }
    : null;
}

const MAX_CALENDAR_WINDOWS = 100_000;

/** Start of the window of `interval` that contains `now`, as Rafiki's `getInterval` finds it; `null` when none does. */
function repeatingWindowStart(interval: RepeatingInterval, now: number): Date | null {
  const { start, end, step, forward, repetitions } = interval;

  if (start <= now && now < end) return new Date(start);

  // Before the first window of a forward series, after the first of a backward one: no window ever contains `now`.
  if (forward ? start > now : end <= now) return null;
  const fixedMs = step === null ? end - start : step.years === 0 && step.months === 0 ? durationMs(step) : null;

  if (fixedMs !== null) {
    // Equal-length windows: jump to the right one instead of walking.
    const windows = forward ? Math.floor((now - end) / fixedMs) + 1 : Math.ceil((start - now) / fixedMs);

    if (windows > repetitions) return null;

    return new Date(forward ? end + (windows - 1) * fixedMs : start - windows * fixedMs);
  }

  if (step === null) return null;
  let windowStart = start;
  let windowEnd = end;

  // Calendar windows differ in length: walk them, chained from the previous one like Rafiki does.
  for (let window = 1; window <= repetitions && window <= MAX_CALENDAR_WINDOWS; window += 1) {
    const nextStart = forward ? windowEnd : shift(windowStart, step, -1);
    const nextEnd = forward ? shift(windowEnd, step, 1) : windowStart;

    if (nextStart <= now && now < nextEnd) return new Date(nextStart);
    windowStart = nextStart;
    windowEnd = nextEnd;
  }

  return null;
}

/**
 * Converts `limits.interval` to the length of one window in milliseconds: a repeating interval's period (the
 * first window's length for `R/start/end`) or a plain ISO-8601 duration. Years count as 365 days and months as
 * 30 days here; {@link currentAccessIntervalStart} uses the UTC calendar for windows containing them. Returns
 * `null` for malformed or non-positive values.
 */
export function parseAccessIntervalMs(value: string): number | null {
  if (value.startsWith("R")) {
    const repeating = parseRepeating(value);

    if (repeating === null) return null;

    return repeating.step === null ? repeating.end - repeating.start : durationMs(repeating.step);
  }

  const parts = parseAccessIntervalParts(value);

  return parts === null ? null : durationMs(parts);
}

/**
 * Start of the spend window containing `now`. `interval` is the ISO 8601 repeating interval of Open Payments
 * (`R12/2019-08-24T14:15:22Z/P1M`, `R/2017-03-01T13:00:00Z/2018-05-11T15:30:00Z`, `R-1/P1Y2M10DT2H30M/2022-05-11T15:30:00Z`)
 * with Rafiki's semantics: windows are half-open, the first one plus `n` repetitions (all of them for `R` and `R-1`),
 * and `null` when `now` lies in none (before the first window, after the last). A plain duration (`P1M`) is also
 * accepted: windows of that length repeating from `anchor`, the grant's creation time; `null` when `anchor` is not in
 * the past. A malformed `interval` is `null`.
 *
 * @see https://openpayments.dev/concepts/grant-limits
 */
export function currentAccessIntervalStart(anchor: Date, interval: string, now: Date = new Date()): Date | null {
  if (interval.startsWith("R")) {
    const repeating = parseRepeating(interval);

    return repeating === null ? null : repeatingWindowStart(repeating, now.getTime());
  }

  const parts = parseAccessIntervalParts(interval);
  const duration = parseAccessIntervalMs(interval);

  if (!parts || !duration || !Number.isFinite(anchor.getTime()) || anchor.getTime() > now.getTime()) return null;

  if (parts.years === 0 && parts.months === 0) {
    const cycles = Math.floor((now.getTime() - anchor.getTime()) / duration);

    return new Date(anchor.getTime() + cycles * duration);
  }

  let start = new Date(anchor);

  for (let step = 0; step < MAX_CALENDAR_WINDOWS; step++) {
    const next = addAccessInterval(start, parts);

    if (next.getTime() > now.getTime()) return start;
    start = next;
  }

  return null;
}

function withinCap(cap: Amount | undefined, amount: Amount): boolean {
  if (!cap) return true;

  if (cap.assetCode !== amount.assetCode || cap.assetScale !== amount.assetScale) return false;
  const limit = parseAmountValue(cap.value, UINT128_MAX);
  const value = parseAmountValue(amount.value, UINT128_MAX);

  return Result.isSuccess(limit) && Result.isSuccess(value) && value.success <= limit.success;
}

/**
 * Whether an outgoing payment's amounts fit the `debitAmount` / `receiveAmount` limits of the matched access
 * items. An item without the relevant limit does not constrain; with no limits at all the payment is allowed, but
 * with no matched item nothing authorizes it. A limit in another asset code or scale cannot be compared and rejects
 * the payment, as does a malformed value.
 */
export function validateOutgoingPaymentAmounts(
  matchedAccess: AccessMatchItem[],
  debit: Amount,
  receive: Amount | undefined,
): boolean {
  return (
    matchedAccess.length > 0 &&
    matchedAccess.every(
      (access) =>
        withinCap(access.limits?.debitAmount, debit) && (!receive || withinCap(access.limits?.receiveAmount, receive)),
    )
  );
}

function matches(requestItem: AccessMatchItem, grantItem: AccessMatchItem): boolean {
  if (requestItem.type !== grantItem.type) return false;

  if (requestItem.actions) {
    const grantActions = new Set(grantItem.actions ?? []);

    // `read-all` / `list-all` also satisfy a `read` / `list` requirement.
    const allRequested = requestItem.actions.every(
      (action) =>
        grantActions.has(action) || ((action === "read" || action === "list") && grantActions.has(`${action}-all`)),
    );

    if (!allRequested) return false;
  }

  return (requestItem.identifier ?? null) === (grantItem.identifier ?? null);
}

function canonicalUrl(value: string): string | null {
  try {
    return new URL(value).href;
  } catch {
    return null;
  }
}

/** An encoded `.`, `/` or `\`: a server that decodes it may read the child path as a way out of the limit. */
const ENCODED_PATH_CHARACTER = /%(?:2e|2f|5c)/i;

/**
 * Whether `receiverUrl` is allowed by the `limits.receiver` of any matched access item (exact URL or a child path
 * without encoded `.`, `/` or `\`). `fetch` resolves URLs after WHATWG normalisation, so a receiver that is not
 * already in canonical form (dot segments, `%2e%2e`, credentials, fragments, upper-case host, …) could resolve to
 * another resource while passing a string comparison; such receivers are rejected. An item without a receiver limit
 * allows any receiver.
 */
export function validateOutgoingPaymentReceiver(matchedAccess: AccessMatchItem[], receiverUrl: string): boolean {
  if (matchedAccess.length === 0) return false;
  const receiver = canonicalUrl(receiverUrl);

  for (const access of matchedAccess) {
    const limit = access.limits?.receiver;

    if (!limit) return true;

    if (receiver === null || receiver !== receiverUrl) continue;
    const allowed = canonicalUrl(limit);

    if (allowed === null) continue;

    if (receiver === allowed) return true;

    const prefix = allowed.endsWith("/") ? allowed : `${allowed}/`;

    if (receiver.startsWith(prefix) && !ENCODED_PATH_CHARACTER.test(receiver.slice(prefix.length))) return true;
  }

  return false;
}

/**
 * Matches the access items a request asks for against a grant's access items and returns the grant items that
 * satisfy them. An item matches on equal `type` and `identifier` and when it grants every requested action
 * (`read-all` / `list-all` satisfy `read` / `list`). When several grant items match, one carrying the
 * requested action's `-all` variant is preferred so handlers can tell the grant covers every client's resources.
 * An absent or empty request returns all grant items.
 *
 * @see https://openpayments.dev/apis/token-introspection/
 */
export function compareRequestAndGrantAccessItems(
  requestAccess: AccessMatchItem[] | undefined,
  grantAccesses: AccessMatchItem[],
): AccessMatchItem[] {
  if (!requestAccess || requestAccess.length === 0) return grantAccesses;
  const result: AccessMatchItem[] = [];

  for (const request of requestAccess) {
    const candidates = grantAccesses.filter((grant) => matches(request, grant));

    const matched =
      candidates.find((grant) => request.actions?.some((action) => grant.actions?.includes(`${action}-all`))) ??
      candidates[0];

    if (matched) result.push(matched);
  }

  return result;
}
