// SPDX-License-Identifier: GPL-3.0-or-later
// A moment as it reads in a log: the time for today, the date and time for earlier days, in the
// OS locale via Intl (English only for now, no i18n framework).

const timeFormats = new Map<string, Intl.DateTimeFormat>();
const dayFormats = new Map<string, Intl.DateTimeFormat>();

function format(
  cache: Map<string, Intl.DateTimeFormat>,
  locale: string | undefined,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat {
  const key = locale ?? "";
  let found = cache.get(key);
  if (!found) {
    found = new Intl.DateTimeFormat(locale, options);
    cache.set(key, found);
  }
  return found;
}

/** Midnight at the start of the local day `ms` falls in. */
export function startOfDay(ms: number): number {
  const date = new Date(ms);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/** `14:03:22` for a moment on or after `dayStart`, `Oct 6, 14:03:22` before it. */
export function clockTime(
  ms: number,
  dayStart: number,
  locale?: string,
): string {
  const time = format(timeFormats, locale, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(ms);
  if (ms >= dayStart) return time;
  const day = format(dayFormats, locale, {
    month: "short",
    day: "numeric",
  }).format(ms);
  return `${day}, ${time}`;
}
