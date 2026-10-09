// SPDX-License-Identifier: GPL-3.0-or-later
//! `GET /api/doctor` over real HTTP: the fake, the real service over a canned check, the refusals.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use puddle_api::wire::DoctorStatus;
use puddle_api::{FakeDoctor, HostDoctor};
use puddle_doctor::{Check, CheckId, Finding, Report, Status};
use serde_json::{Value, json};

use crate::common::{start, start_with_doctor};

#[tokio::test]
async fn without_a_service_the_check_says_it_is_unavailable() {
    let api = start().await;
    let reply = api.get("/api/doctor").await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.error(), "unavailable");
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_check_needs_the_token() {
    let api = start().await;
    let request = format!(
        "GET /api/doctor HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        api.host()
    );
    let reply = crate::common::raw(api.addr, request.as_bytes()).await;
    assert_eq!(reply.status, 401);
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_fake_reports_a_healthy_machine_with_every_field_present() {
    let api = start_with_doctor(Arc::new(FakeDoctor::new())).await;
    let reply = api.get("/api/doctor").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["ok"], true);
    let first = &body["checks"][0];
    assert_eq!(first["id"], "virtualization");
    assert_eq!(first["title"], "CPU virtualization");
    assert_eq!(first["status"], "ok");
    assert_eq!(
        (&first["finding"], &first["fix"], &first["detail"]),
        (&Value::Null, &Value::Null, &Value::Null),
        "a check with nothing to say carries nulls, not missing fields"
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_boot_query_decides_whether_the_test_boot_runs() {
    let api = start_with_doctor(Arc::new(FakeDoctor::new())).await;
    let status_of_boot = |body: Value| {
        body["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "test_boot")
            .map(|c| c["status"].clone())
            .unwrap()
    };
    let default = api.get("/api/doctor").await.json();
    assert_eq!(status_of_boot(default), "ok");
    let quick = api.get("/api/doctor?boot=false").await.json();
    assert_eq!(status_of_boot(quick), "skipped");
    let explicit = api.get("/api/doctor?boot=true").await.json();
    assert_eq!(status_of_boot(explicit), "ok");

    let reply = api.get("/api/doctor?boot=maybe").await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert_eq!(reply.error(), "bad_request");
    let reply = api.get("/api/doctor?quick=1").await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_failed_check_carries_its_finding_and_fix() {
    let fake = Arc::new(FakeDoctor::new());
    let mut broken = FakeDoctor::healthy();
    broken.ok = false;
    broken.checks[1].status = DoctorStatus::Fail;
    broken.checks[1].summary = "KVM is missing".into();
    broken.checks[1].finding = Some("kvm_missing".into());
    broken.checks[1].fix = Some("Turn it on.".into());
    fake.set(broken);
    let api = start_with_doctor(fake).await;
    let body = api.get("/api/doctor").await.json();
    assert_eq!(body["ok"], false);
    assert_eq!(
        body["checks"][1],
        json!({
            "id": "hypervisor", "title": "Hypervisor", "status": "fail",
            "summary": "KVM is missing", "finding": "kvm_missing",
            "fix": "Turn it on.", "detail": null
        })
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_real_service_serves_what_its_checks_found() {
    let run = Arc::new(|boot: bool| Report {
        schema_version: puddle_doctor::SCHEMA_VERSION,
        puddle_version: "1.2.3".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        ok: false,
        checks: vec![Check {
            id: CheckId::TestBoot,
            status: Status::Fail,
            summary: format!("boot asked for: {boot}"),
            finding: Some(Finding::BootFailed),
            fix: Some("Fix it.".into()),
            detail: Some("exit code 1".into()),
        }],
        elapsed_ms: 12,
    });
    let api = start_with_doctor(Arc::new(HostDoctor::new(run))).await;
    let body = api.get("/api/doctor?boot=false").await.json();
    assert_eq!(body["puddle_version"], "1.2.3");
    assert_eq!(body["ok"], false);
    assert_eq!(
        body["checks"][0],
        json!({
            "id": "test_boot", "title": "Test boot", "status": "fail",
            "summary": "boot asked for: false", "finding": "boot_failed",
            "fix": "Fix it.", "detail": "exit code 1"
        })
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_check_that_crashes_is_an_internal_error_and_the_api_goes_on() {
    let crashed = Arc::new(AtomicBool::new(false));
    let seen = crashed.clone();
    let run = Arc::new(move |_boot: bool| -> Report {
        seen.store(true, Ordering::SeqCst);
        panic!("probe blew up")
    });
    let api = start_with_doctor(Arc::new(HostDoctor::new(run))).await;
    let reply = api.get("/api/doctor").await;
    assert_eq!(reply.status, 500, "{}", reply.body);
    assert_eq!(reply.error(), "internal");
    assert!(crashed.load(Ordering::SeqCst));
    assert_eq!(api.get("/api/health").await.status, 200);
    api.running.shutdown().await;
}
