// SPDX-License-Identifier: GPL-3.0-or-later
//! Property tests for resolution and for documents (round trip, unknown fields, versions).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions fail the test by panicking"
)]

use proptest::prelude::*;
use puddle_settings::{
    ClipboardRead, Consent, ConsentKind, Effective, GLOBAL_SCHEMA_VERSION, GlobalSettings,
    ReconnectionGrace, Resolved, SANDBOX_SCHEMA_VERSION, SandboxLayer, SandboxSettings,
    SettingsError, Source, TermsVersion, UnixMillis, resolve,
};
use puddle_types::MemoryMib;
use serde_json::{Value, json};

fn memory() -> impl Strategy<Value = MemoryMib> {
    (MemoryMib::MIN.get()..=MemoryMib::MAX.get()).prop_map(|m| MemoryMib::new(m).unwrap())
}

fn grace() -> impl Strategy<Value = ReconnectionGrace> {
    (ReconnectionGrace::MIN.secs()..=ReconnectionGrace::MAX.secs())
        .prop_map(|s| ReconnectionGrace::new(s).unwrap())
}

fn clipboard() -> impl Strategy<Value = ClipboardRead> {
    prop_oneof![
        Just(ClipboardRead::Ask),
        Just(ClipboardRead::Allow),
        Just(ClipboardRead::Deny)
    ]
}

fn layer() -> impl Strategy<Value = SandboxLayer> {
    (
        proptest::option::of(memory()),
        proptest::array::uniform5(proptest::option::of(any::<bool>())),
        proptest::option::of(any::<bool>()),
        proptest::option::of(grace()),
        proptest::option::of(any::<bool>()),
        proptest::option::of(clipboard()),
        proptest::option::of(any::<bool>()),
    )
        .prop_map(|(memory, toggles, wild, grace, zoom, clip, direct_ssh)| {
            let mut l = SandboxLayer::default();
            l.memory = memory;
            let [loopback, private, link_local, metadata, special] = toggles;
            l.local_toggles.loopback = loopback;
            l.local_toggles.private = private;
            l.local_toggles.link_local = link_local;
            l.local_toggles.metadata = metadata;
            l.local_toggles.special = special;
            l.wildcards_reach_local = wild;
            l.reconnection_grace = grace;
            l.zoom_hotkeys = zoom;
            l.clipboard_read = clip;
            l.direct_ssh = direct_ssh;
            l
        })
}

fn consent() -> impl Strategy<Value = Consent> {
    let terms = "[!-~]{1,40}".prop_map(|s| TermsVersion::new(&s).unwrap());
    prop_oneof![
        Just(Consent::NotAsked),
        (any::<u64>(), terms.clone()).prop_map(|(at, terms_version)| Consent::Granted {
            at: UnixMillis(at),
            terms_version
        }),
        (any::<u64>(), terms).prop_map(|(at, terms_version)| Consent::Declined {
            at: UnixMillis(at),
            terms_version
        }),
    ]
}

fn global() -> impl Strategy<Value = GlobalSettings> {
    (
        layer(),
        proptest::option::of(any::<bool>()),
        proptest::option::of(any::<bool>()),
        proptest::array::uniform3(consent()),
    )
        .prop_map(|(defaults, telemetry, auto_update, consents)| {
            let mut g = GlobalSettings::default();
            g.sandbox_defaults = defaults;
            g.vscode_server.telemetry = telemetry;
            g.vscode_server.auto_update = auto_update;
            for (kind, c) in ConsentKind::ALL.into_iter().zip(consents) {
                g.consents.set(kind, c);
            }
            g
        })
}

fn sandbox() -> impl Strategy<Value = SandboxSettings> {
    layer().prop_map(|overrides| {
        let mut s = SandboxSettings::default();
        s.overrides = overrides;
        s
    })
}

/// The rule, written out once more independently of `resolve`.
fn expect<T: Copy + PartialEq + std::fmt::Debug>(
    got: Resolved<T>,
    sandbox: Option<T>,
    global: Option<T>,
    builtin: T,
) {
    let want = match (sandbox, global) {
        (Some(v), _) => (v, Source::Sandbox),
        (None, Some(v)) => (v, Source::Global),
        (None, None) => (builtin, Source::Default),
    };
    assert_eq!((got.value, got.source), want);
}

fn check_rule(g: &GlobalSettings, s: Option<&SandboxSettings>) {
    let eff = resolve(g, s);
    let empty = SandboxLayer::default();
    let over = s.map_or(&empty, |s| &s.overrides);
    let glob = &g.sandbox_defaults;
    let builtin = Effective::DEFAULTS;
    expect(eff.memory, over.memory, glob.memory, builtin.memory.value);
    expect(
        eff.local_toggles.loopback,
        over.local_toggles.loopback,
        glob.local_toggles.loopback,
        false,
    );
    expect(
        eff.local_toggles.private,
        over.local_toggles.private,
        glob.local_toggles.private,
        false,
    );
    expect(
        eff.local_toggles.link_local,
        over.local_toggles.link_local,
        glob.local_toggles.link_local,
        false,
    );
    expect(
        eff.local_toggles.metadata,
        over.local_toggles.metadata,
        glob.local_toggles.metadata,
        false,
    );
    expect(
        eff.local_toggles.special,
        over.local_toggles.special,
        glob.local_toggles.special,
        false,
    );
    expect(
        eff.wildcards_reach_local,
        over.wildcards_reach_local,
        glob.wildcards_reach_local,
        false,
    );
    expect(
        eff.reconnection_grace,
        over.reconnection_grace,
        glob.reconnection_grace,
        ReconnectionGrace::DEFAULT,
    );
    expect(eff.zoom_hotkeys, over.zoom_hotkeys, glob.zoom_hotkeys, true);
    expect(
        eff.clipboard_read,
        over.clipboard_read,
        glob.clipboard_read,
        ClipboardRead::Ask,
    );
    expect(eff.direct_ssh, over.direct_ssh, glob.direct_ssh, false);
}

/// Keys that no settings struct knows, at any level.
fn unknown_key() -> impl Strategy<Value = String> {
    "x_[a-z0-9_]{0,12}"
}

proptest! {
    #[test]
    fn override_beats_global_beats_default(g in global(), s in sandbox()) {
        check_rule(&g, Some(&s));
        check_rule(&g, None);
    }

    #[test]
    fn an_empty_override_layer_inherits_everything(g in global()) {
        let empty = SandboxSettings::default();
        prop_assert_eq!(resolve(&g, Some(&empty)), resolve(&g, None));
    }

    #[test]
    fn a_full_override_layer_ignores_the_global_level(g1 in global(), g2 in global(), s in sandbox()) {
        // Fill every override, then the global level makes no difference.
        let mut full = s;
        let o = &mut full.overrides;
        o.memory.get_or_insert(MemoryMib::DEFAULT);
        o.local_toggles.loopback.get_or_insert(true);
        o.local_toggles.private.get_or_insert(true);
        o.local_toggles.link_local.get_or_insert(true);
        o.local_toggles.metadata.get_or_insert(true);
        o.local_toggles.special.get_or_insert(true);
        o.wildcards_reach_local.get_or_insert(true);
        o.reconnection_grace.get_or_insert(ReconnectionGrace::MIN);
        o.zoom_hotkeys.get_or_insert(false);
        o.clipboard_read.get_or_insert(ClipboardRead::Deny);
        o.direct_ssh.get_or_insert(true);
        prop_assert_eq!(resolve(&g1, Some(&full)), resolve(&g2, Some(&full)));
    }

    #[test]
    fn global_documents_round_trip(g in global()) {
        let doc = g.to_document();
        prop_assert_eq!(&doc["schema_version"], &json!(GLOBAL_SCHEMA_VERSION));
        let loaded = GlobalSettings::from_document(doc).unwrap();
        prop_assert_eq!(loaded.settings, g);
        prop_assert_eq!(loaded.migrated_from, None);
        prop_assert!(loaded.unknown_fields.is_empty());
    }

    #[test]
    fn sandbox_documents_round_trip(s in sandbox()) {
        let doc = s.to_document();
        prop_assert_eq!(&doc["schema_version"], &json!(SANDBOX_SCHEMA_VERSION));
        prop_assert_eq!(SandboxSettings::from_document(doc).unwrap().settings, s);
    }

    #[test]
    fn unknown_fields_survive_a_read_and_write_at_every_level(
        g in global(),
        keys in proptest::collection::btree_set(unknown_key(), 1..4),
        value in prop_oneof![
            any::<bool>().prop_map(Value::from),
            any::<i64>().prop_map(Value::from),
            "[ -~]{0,20}".prop_map(Value::from),
            Just(json!({"nested": [1, null, "x"]})),
        ],
    ) {
        let mut doc = g.to_document();
        let mut paths = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let parent = ["", "sandbox_defaults", "vscode_server", "consents"][i % 4];
            let target = if parent.is_empty() {
                &mut doc
            } else {
                doc.as_object_mut().unwrap().entry(parent).or_insert_with(|| json!({}))
            };
            target.as_object_mut().unwrap().insert(key.clone(), value.clone());
            paths.push(if parent.is_empty() { key.clone() } else { format!("{parent}.{key}") });
        }
        let loaded = GlobalSettings::from_document(doc.clone()).unwrap();
        let mut listed = loaded.unknown_fields.clone();
        listed.sort();
        paths.sort();
        prop_assert_eq!(listed, paths);
        prop_assert_eq!(loaded.settings.to_document(), doc);
    }

    #[test]
    fn newer_schema_versions_are_refused(v in (GLOBAL_SCHEMA_VERSION + 1)..=u32::MAX) {
        let err = GlobalSettings::from_document(json!({"schema_version": v})).unwrap_err();
        let refused = matches!(err, SettingsError::NewerSchema { found, .. } if found == v);
        prop_assert!(refused);
        let err = SandboxSettings::from_document(json!({"schema_version": v})).unwrap_err();
        let refused = matches!(err, SettingsError::NewerSchema { .. });
        prop_assert!(refused);
    }

    #[test]
    fn arbitrary_json_never_panics(doc in arb_json()) {
        let _ = GlobalSettings::from_document(doc.clone());
        let _ = SandboxSettings::from_document(doc);
    }
}

fn arb_json() -> impl Strategy<Value = Value> {
    let key = prop_oneof![
        Just("schema_version".to_owned()),
        Just("sandbox_defaults".to_owned()),
        Just("overrides".to_owned()),
        Just("memory".to_owned()),
        Just("local_toggles".to_owned()),
        Just("consents".to_owned()),
        Just("telemetry".to_owned()),
        Just("state".to_owned()),
        "[a-z_]{1,8}",
    ];
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u32>().prop_map(Value::from),
        any::<f64>().prop_map(Value::from),
        "[ -~]{0,10}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 48, 6, move |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            proptest::collection::btree_map(key.clone(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}
