// SPDX-License-Identifier: GPL-3.0-or-later
// "3 minutes ago", via Intl in the OS locale (English only for now, no i18n framework).

const STEPS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400],
  ["hour", 3600],
  ["minute", 60],
];

// Building an Intl formatter costs far more than using one; a long list asks for thousands.
const relativeFormats = new Map<string, Intl.RelativeTimeFormat>();
const dateFormats = new Map<string, Intl.DateTimeFormat>();

function relativeFormat(locale: string | undefined): Intl.RelativeTimeFormat {
  const key = locale ?? "";
  let format = relativeFormats.get(key);
  if (!format) {
    format = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
    relativeFormats.set(key, format);
  }
  return format;
}

/** The medium date and time in `locale`. */
function dateTimeFormat(locale?: string): Intl.DateTimeFormat {
  const key = locale ?? "";
  let format = dateFormats.get(key);
  if (!format) {
    format = new Intl.DateTimeFormat(locale, {
      dateStyle: "medium",
      timeStyle: "medium",
    });
    dateFormats.set(key, format);
  }
  return format;
}

/** How a moment reads next to `now`; under 10 seconds is "just now". */
export function relativeTime(
  then: number,
  now: number,
  locale?: string,
): string {
  const seconds = Math.round((then - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 10) return "just now";
  const rtf = relativeFormat(locale);
  for (const [unit, size] of STEPS) {
    if (abs >= size) return rtf.format(Math.trunc(seconds / size), unit);
  }
  return rtf.format(seconds, "second");
}

/** The full date and time, for a tooltip and the `datetime` attribute's reader. */
export function absoluteTime(ms: number, locale?: string): string {
  return dateTimeFormat(locale).format(ms);
}
