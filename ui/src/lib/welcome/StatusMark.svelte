<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { STATUS_LABEL, STATUS_MARK, type DoctorStatus } from "./doctor.ts";

  // The round symbol in front of a check. The word for it is in the text for screen readers: the
  // colour and the glyph are never the only signal.
  let { status }: { status: DoctorStatus } = $props();
</script>

<span class="mark {status}" aria-hidden="true">{STATUS_MARK[status]}</span>
<span class="visually-hidden">{STATUS_LABEL[status]}: </span>

<style>
  .mark {
    flex: none;
    display: grid;
    place-items: center;
    width: 1.5rem;
    height: 1.5rem;
    border-radius: 50%;
    border: 2px solid currentColor;
    font-size: var(--text-sm);
    font-weight: 800;
    line-height: 1;
  }
  .ok {
    color: var(--color-success);
  }
  .info,
  .skipped {
    color: var(--color-text-muted);
  }
  .warn {
    color: var(--color-warning);
  }
  .fail {
    color: var(--color-danger);
  }
</style>
