#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::Value;

    #[test]
    fn csp_and_capability_remain_explicit_and_minimal() {
        let configuration: Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid Tauri config");
        let security = &configuration["app"]["security"];
        assert_eq!(
            security["capabilities"],
            serde_json::json!(["default", "android"])
        );
        let csp = security["csp"].as_object().expect("CSP object");
        for directive in [
            "default-src",
            "connect-src",
            "font-src",
            "img-src",
            "style-src",
            "script-src",
            "object-src",
            "base-uri",
            "frame-src",
            "form-action",
        ] {
            assert!(
                csp.contains_key(directive),
                "missing CSP directive {directive}"
            );
        }
        assert_eq!(csp["object-src"], "'none'");
        assert_eq!(csp["base-uri"], "'none'");
        assert!(
            !csp["script-src"]
                .as_str()
                .unwrap_or_default()
                .contains("unsafe")
        );

        let capability: Value = serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("valid capability");
        assert_eq!(capability["windows"], serde_json::json!(["main"]));
        assert_eq!(capability["local"], true);
        assert_eq!(
            capability["platforms"],
            serde_json::json!(["linux", "windows", "macOS"])
        );
        let permissions = capability["permissions"]
            .as_array()
            .expect("permission list");
        let identifiers = permissions
            .iter()
            .filter_map(|permission| {
                permission
                    .as_str()
                    .or_else(|| permission.get("identifier").and_then(Value::as_str))
            })
            .collect::<HashSet<_>>();
        for forbidden in [
            "core:default",
            "opener:default",
            "dialog:default",
            "updater:default",
            "process:default",
        ] {
            assert!(
                !identifiers.contains(forbidden),
                "broad permission {forbidden}"
            );
        }
        for required in [
            "core:event:allow-listen",
            "core:event:allow-unlisten",
            "dialog:allow-open",
            "updater:allow-check",
            "updater:allow-download-and-install",
            "process:allow-restart",
        ] {
            assert!(
                identifiers.contains(required),
                "missing used permission {required}"
            );
        }
    }

    #[test]
    fn custom_command_manifest_matches_handler_and_capability() {
        let commands = include_str!("../command_manifest.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<HashSet<_>>();
        assert_eq!(
            commands.len(),
            73,
            "command manifest contains duplicates or changed count"
        );

        let source = include_str!("lib.rs");
        let handler = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .and_then(|value| value.split("])").next())
            .expect("invoke handler source segment");
        let handler_commands = handler
            .split(',')
            .filter_map(|entry| entry.trim().split("::").last())
            .filter(|entry| !entry.is_empty())
            .collect::<HashSet<_>>();
        for command in &commands {
            assert!(
                handler_commands.contains(command),
                "{command} missing from invoke handler"
            );
        }

        let desktop: Value = serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("valid desktop capability");
        let android: Value = serde_json::from_str(include_str!("../capabilities/android.json"))
            .expect("valid Android capability");
        assert_eq!(android["platforms"], serde_json::json!(["android"]));
        let identifiers = desktop["permissions"]
            .as_array()
            .expect("desktop permission list")
            .iter()
            .chain(
                android["permissions"]
                    .as_array()
                    .expect("Android permission list"),
            )
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>();
        for command in commands {
            let permission = format!("allow-{}", command.replace('_', "-"));
            assert!(
                identifiers.contains(permission.as_str()),
                "missing {permission}"
            );
        }

        let android_permissions = android["permissions"]
            .as_array()
            .expect("Android permissions")
            .iter()
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>();
        for forbidden in [
            "allow-start-ssh-session",
            "allow-preview-broadcast",
            "allow-begin-external-edit",
            "allow-start-remote-monitor",
            "dialog:allow-open",
            "updater:allow-check",
            "process:allow-restart",
            "allow-sync-run-once",
            "allow-sync-attach-session",
            "allow-sync-acknowledge-reconciliation",
            "allow-native-engine-probe",
            "allow-cancel-native-engine-operation",
            "allow-start-native-terminal",
            "allow-native-list-remote-files",
            "allow-ack-native-terminal-output",
        ] {
            assert!(!android_permissions.contains(forbidden));
        }
        assert!(android_permissions.contains("allow-android-sync-status"));
        assert!(android_permissions.contains("allow-android-security-status"));
        assert!(android_permissions.contains("allow-android-unlock"));
        assert!(android_permissions.contains("allow-android-enter-background"));
        assert!(!android_permissions.contains("allow-android-set-lifecycle"));
        assert!(
            !android_permissions
                .iter()
                .any(|permission| permission.starts_with("biometric:"))
        );

        let terminal = include_str!("../../src/components/TerminalView.tsx");
        assert!(terminal.contains("ack_native_terminal_output"));
        assert!(terminal.contains("deliveryId <= nativeDeliveryRef.current.last"));
        assert!(terminal.contains("nativeDeliveryRef.current.pending.has(deliveryId)"));
        assert!(include_str!("../../src/App.tsx").contains("sessions.map((session)"));
    }

    #[test]
    fn frontend_business_state_has_no_local_storage_write_path() {
        for (name, source) in [
            (
                "state hook",
                include_str!("../../src/hooks/usePersistedState.ts"),
            ),
            (
                "file panel",
                include_str!("../../src/components/FileTransferPanel.tsx"),
            ),
            ("application", include_str!("../../src/App.tsx")),
        ] {
            assert!(
                !source.contains("localStorage.setItem"),
                "{name} writes localStorage"
            );
        }
    }

    #[test]
    fn native_jump_route_is_explicit_and_fail_closed_in_frontend() {
        let frontend = include_str!("../../src/App.tsx");
        let types = include_str!("../../src/types.ts");
        assert!(types.contains("jumpRoute?: string[]"));
        assert!(frontend.contains("nativeRouteHosts(host, hosts)"));
        assert!(frontend.contains("jumpRoute.length > 3"));
        assert!(frontend.contains("new Set(routeIds).size !== routeIds.length"));
        assert!(frontend.contains("targetHostKeySha256 ?? routeHost.hostKeySha256"));
        assert!(frontend.contains("activeSession.engine !== \"russh\""));
        assert!(frontend.contains("routeHost.identityFile ? undefined : routeHost.credentialRef"));
        assert!(!frontend.contains("nativeDirectRoute"));
    }

    #[test]
    fn credential_sync_has_no_ipc_event_or_logging_surface() {
        let source = include_str!("sync_credential_vault.rs");
        for forbidden in [
            "#[tauri::command]",
            ".emit(",
            "println!",
            "eprintln!",
            "dbg!",
            "tracing::",
            "log::",
        ] {
            assert!(
                !source.contains(forbidden),
                "credential vault exposes forbidden surface: {forbidden}"
            );
        }
        assert!(!include_str!("../command_manifest.txt").contains("credential_vault"));
    }

    #[test]
    fn android_shell_blocks_backup_screenshots_cleartext_and_external_file_sharing() {
        let manifest = include_str!("../gen/android/app/src/main/AndroidManifest.xml");
        let activity =
            include_str!("../gen/android/app/src/main/java/com/sanro/vpshell/MainActivity.kt");
        let gradle = include_str!("../gen/android/app/build.gradle.kts");

        assert!(manifest.contains("android:allowBackup=\"false\""));
        assert_eq!(manifest.matches("<uses-permission").count(), 1);
        assert!(manifest.contains("android.permission.INTERNET"));
        assert!(!manifest.contains("FileProvider"));
        assert!(!manifest.contains("external-path"));
        assert!(activity.contains("WindowManager.LayoutParams.FLAG_SECURE"));
        assert!(activity.contains("vpshell-native-background"));
        assert!(activity.contains("vpshell-native-resume"));
        assert!(activity.contains("WebViewCompat.addWebMessageListener"));
        assert!(activity.contains("http://tauri.localhost"));
        assert!(!activity.contains("addJavascriptInterface"));
        assert!(!activity.contains("setOf(\"*\")"));
        assert!(activity.contains("if (BuildConfig.DEBUG)"));
        assert!(activity.contains("IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS"));
        assert!(activity.contains("IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS"));
        assert!(activity.contains("setOnLongClickListener { true }"));
        assert!(activity.contains("MAX_VISIBILITY_MESSAGE_BYTES = 32"));
        assert!(activity.contains("webView.visibility = View.INVISIBLE"));
        assert!(!activity.contains("BiometricPrompt"));
        assert!(!activity.contains("SharedPreferences"));
        assert!(!gradle.contains("usesCleartextTraffic\"] = \"true\""));
        assert!(!gradle.contains("androidx.biometric:biometric"));

        let frontend = include_str!("../../src/androidSecurity.ts");
        assert!(frontend.contains("requestAndroidSecurity"));
        assert!(frontend.contains("android_unlock"));
        assert!(!frontend.contains("password"));
        assert!(!frontend.contains("privateKey"));

        let source = include_str!("android_mobile.rs");
        for forbidden in ["println!", "eprintln!", "dbg!", "tracing::", "log::"] {
            assert!(!source.contains(forbidden));
        }
        assert!(!source.contains("Serialize)]\npub(crate) struct AndroidStoreCredentialRequest"));
        assert!(source.contains("tauri_plugin_biometric::BiometricExt"));
        assert!(source.contains("AndroidPreviewOperation::CredentialVault"));
        assert!(source.contains("AndroidPreviewOperation::Connect"));
        assert!(!source.contains("pub(crate) fn android_set_lifecycle"));

        let cargo = include_str!("../Cargo.toml");
        assert!(cargo.contains("tauri-plugin-biometric = \"=2.3.2\""));
    }
}
