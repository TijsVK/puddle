// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows only: the job object and the front process. All `unsafe` is in [`sys`].

pub(crate) mod front;
pub(crate) mod job;
mod sys;
