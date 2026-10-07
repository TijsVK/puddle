// SPDX-License-Identifier: GPL-3.0-or-later
//! Test harness for end-to-end and hostile-guest tests (T-032 tiers L2-L4, T-035 tiers P/V/W): fake upstreams, guest drivers, audit-log assertions; and the UI fixture backend ([`ui_fixture`], T-171). Test and development code only; never a dependency of product crates.
#![forbid(unsafe_code)]

pub mod ui_fixture;
