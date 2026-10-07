// SPDX-License-Identifier: GPL-3.0-or-later
//! Test harness for end-to-end and hostile-guest tests (tiers L2-L4 and the hostile-guest tiers P/V/W): fake upstreams, guest drivers, audit-log assertions; and the UI fixture backend ([`ui_fixture`]). Test and development code only; never a dependency of product crates.
#![forbid(unsafe_code)]

pub mod ui_fixture;
