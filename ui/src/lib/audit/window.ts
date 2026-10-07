// SPDX-License-Identifier: GPL-3.0-or-later
// Which rows of a long, fixed-height list to draw. Every row is `rowHeight` tall; one row may be
// open and then is `rowHeight + detailHeight` tall. Pure: the page passes in what it measured.

/** Rows are this tall in px; the table's `--row-h` says the same. */
export const ROW_HEIGHT = 36;
/** An open row's raw record is this tall in px; the table's `--detail-h` says the same. */
export const DETAIL_HEIGHT = 280;

export interface WindowInput {
  scrollTop: number;
  viewportHeight: number;
  rowCount: number;
  rowHeight: number;
  /** Rows drawn beyond the viewport on each side, so a fast scroll has no blank gap. */
  overscan: number;
  /** Index of the open row, or -1. */
  openIndex: number;
  detailHeight: number;
}

export interface WindowRange {
  /** First row drawn. */
  start: number;
  /** One past the last row drawn. */
  end: number;
  /** Height of the rows above `start` that are not drawn. */
  padTop: number;
  /** Height of the rows from `end` on that are not drawn. */
  padBottom: number;
}

/** Top edge of row `index`. */
function offsetOf(input: WindowInput, index: number): number {
  const extra =
    input.openIndex >= 0 && input.openIndex < index ? input.detailHeight : 0;
  return index * input.rowHeight + extra;
}

/** The row a vertical position falls in. */
function rowAt(input: WindowInput, y: number): number {
  const { rowHeight, openIndex, detailHeight, rowCount } = input;
  let position = y;
  if (openIndex >= 0) {
    const openTop = openIndex * rowHeight;
    const openEnd = openTop + rowHeight + detailHeight;
    if (position >= openEnd) position -= detailHeight;
    else if (position > openTop + rowHeight) position = openTop + rowHeight - 1;
  }
  return Math.min(rowCount - 1, Math.max(0, Math.floor(position / rowHeight)));
}

export function visibleRange(input: WindowInput): WindowRange {
  const { rowCount, rowHeight, overscan, detailHeight } = input;
  const openIndex = input.openIndex < rowCount ? input.openIndex : -1;
  if (rowCount === 0) return { start: 0, end: 0, padTop: 0, padBottom: 0 };
  const sized = { ...input, openIndex };
  const first = rowAt(sized, Math.max(0, input.scrollTop));
  const last = rowAt(
    sized,
    Math.max(0, input.scrollTop) + input.viewportHeight,
  );
  const start = Math.max(0, first - overscan);
  const end = Math.min(rowCount, last + 1 + overscan);
  const total = rowCount * rowHeight + (openIndex >= 0 ? detailHeight : 0);
  const drawnHeight =
    (end - start) * rowHeight +
    (openIndex >= start && openIndex < end ? detailHeight : 0);
  const padTop = offsetOf(sized, start);
  return { start, end, padTop, padBottom: total - padTop - drawnHeight };
}
