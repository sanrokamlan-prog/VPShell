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
            98,
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
            "allow-start-mosh-session",
            "allow-preview-broadcast",
            "allow-begin-external-edit",
            "allow-start-remote-monitor",
            "dialog:allow-open",
            "updater:allow-check",
            "process:allow-restart",
            "allow-sync-run-once",
            "allow-sync-attach-session",
            "allow-sync-acknowledge-reconciliation",
            "allow-desktop-sync-status",
            "allow-list-sync-conflicts",
            "allow-configure-local-folder-sync",
            "allow-configure-webdav-sync",
            "allow-configure-sftp-sync",
            "allow-store-webdav-credential",
            "allow-install-webdav-ca",
            "allow-delete-webdav-ca",
            "allow-run-sync-once",
            "allow-resolve-sync-conflict",
            "allow-cancel-sync",
            "allow-lock-sync",
            "allow-native-engine-probe",
            "allow-cancel-native-engine-operation",
            "allow-start-native-terminal",
            "allow-native-list-remote-files",
            "allow-ack-native-terminal-output",
            "allow-start-native-local-forward",
            "allow-list-native-local-forwards",
            "allow-stop-native-local-forward",
            "allow-start-native-remote-forward",
            "allow-list-native-remote-forwards",
            "allow-stop-native-remote-forward",
            "allow-start-native-dynamic-forward",
            "allow-list-native-dynamic-forwards",
            "allow-stop-native-dynamic-forward",
            "allow-start-native-route-measurement",
            "allow-get-native-route-measurement-snapshot",
            "allow-stop-native-route-measurement",
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
    fn desktop_sync_entry_keeps_secrets_in_rust_and_android_read_only() {
        let coordinator = include_str!("sync_coordinator.rs");
        let provider_credentials = include_str!("sync_provider_credentials.rs");
        let provider_ca = include_str!("sync_provider_ca.rs");
        let sftp_provider = include_str!("sync_sftp_provider.rs");
        assert!(coordinator.contains("pub(crate) struct ConfigureLocalFolderSyncRequest"));
        assert!(coordinator.contains("pub(crate) struct ConfigureWebDavSyncRequest"));
        assert!(coordinator.contains("pub(crate) struct ConfigureSftpSyncRequest"));
        assert!(coordinator.contains("let password = Zeroizing::new(request.password)"));
        assert!(
            coordinator
                .contains("const BOOTSTRAP_OBJECT_KEY: &str = \"vpshell/v1/bootstrap.json\"")
        );
        for forbidden in ["println!", "eprintln!", "log::", "tracing::"] {
            assert!(!coordinator.contains(forbidden));
            assert!(!provider_credentials.contains(forbidden));
            assert!(!provider_ca.contains(forbidden));
            assert!(!sftp_provider.contains(forbidden));
        }

        let frontend = include_str!("../../src/App.tsx");
        for command in [
            "desktop_sync_status",
            "list_sync_conflicts",
            "configure_local_folder_sync",
            "configure_webdav_sync",
            "configure_sftp_sync",
            "store_webdav_credential",
            "install_webdav_ca",
            "delete_webdav_ca",
            "run_sync_once",
            "resolve_sync_conflict",
            "cancel_sync",
            "lock_sync",
        ] {
            assert!(frontend.contains(command));
        }
        assert!(frontend.contains("provider === \"sftp\""));
        assert!(frontend.contains("Android Preview 中禁用"));
        let types = include_str!("../../src/types.ts");
        assert!(types.contains("providerCredentialRef?: string"));
        assert!(types.contains("providerCaRef?: string"));
        assert!(types.contains("providerHostId?: string"));
        assert!(!types.contains("providerPassword"));
        assert!(sftp_provider.contains("OpenFlags::EXCLUSIVE"));
        assert!(sftp_provider.contains("Some(RenameFlags::ATOMIC | RenameFlags::NATIVE)"));
        assert!(!sftp_provider.contains("RenameFlags::OVERWRITE"));
        assert!(sftp_provider.contains("connect_pinned"));
        assert!(!sftp_provider.contains("delete_exact"));
    }

    #[test]
    fn relay_is_a_desktop_binary_without_webview_or_secret_audit_surface() {
        let relay = include_str!("relay.rs");
        let binary = include_str!("bin/vpshell-relay.rs");
        let service = include_str!("../../deploy/relay/vpshell-relay.service");
        let environment = include_str!("../../deploy/relay/relay.env.example");
        let logrotate = include_str!("../../deploy/relay/vpshell-relay.logrotate");
        let manifest = include_str!("../command_manifest.txt");
        let desktop = include_str!("../capabilities/default.json");
        let android = include_str!("../capabilities/android.json");

        assert!(!relay.contains("#[tauri::command]"));
        assert!(!manifest.lines().any(|command| command.contains("relay")));
        assert!(!desktop.contains("allow-relay"));
        assert!(!android.contains("allow-relay"));
        assert!(binary.contains("vpshell_lib::relay"));
        assert!(binary.contains("relay-local-listener-must-be-loopback"));
        assert!(relay.contains("const CLIENT_DOMAIN: &[u8] = b\"vpshell-relay-v1-client\""));
        assert!(relay.contains("const SERVER_DOMAIN: &[u8] = b\"vpshell-relay-v1-server\""));
        assert!(relay.contains("MAX_ACTIVE_TOKENS: usize = 4"));
        assert!(relay.contains("pub struct RelayTokenSet"));
        assert!(relay.contains("pub struct RelayAuditEvent"));
        assert!(binary.contains("\"--token-file\" => token_paths.push"));
        assert!(service.contains("NoNewPrivileges=true"));
        assert!(service.contains("ProtectSystem=strict"));
        assert!(service.contains("ReadOnlyPaths=/etc/vpshell-relay"));
        assert!(service.contains("ReadWritePaths=/var/log/vpshell-relay"));
        assert!(service.contains("RestrictAddressFamilies=AF_INET AF_INET6"));
        assert!(!environment.to_ascii_lowercase().contains("token="));
        assert!(logrotate.contains("create 0600 vpshell-relay vpshell-relay"));
        assert!(logrotate.contains("systemctl try-restart vpshell-relay.service"));
        assert!(!logrotate.contains("copytruncate"));
        for forbidden_field in [
            "pub token:",
            "pub key_id:",
            "pub source_address:",
            "pub target_host:",
            "pub payload:",
            "pub error:",
        ] {
            assert!(!relay.contains(forbidden_field));
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
    fn openssh_fallback_is_structured_bounded_and_desktop_only() {
        let backend = include_str!("lib.rs");
        let native = include_str!("native_engine.rs");
        let frontend = include_str!("../../src/App.tsx");
        let android = include_str!("../capabilities/android.json");
        assert!(backend.contains("rename_all = \"camelCase\", deny_unknown_fields"));
        assert!(backend.contains("StrictHostKeyChecking=yes"));
        assert!(backend.contains("NumberOfPasswordPrompts=1"));
        assert!(backend.contains("OPENSSH_ENGINE_NAME"));
        assert!(native.contains("fn with_terminal_fallback"));
        assert!(native.contains("route_hops == 1"));
        assert!(frontend.contains("nativeOpenSshFallbackCodes"));
        assert!(frontend.contains("canFallbackNativeTerminalToOpenSsh(error)"));
        assert!(frontend.contains("result.engine !== \"openssh\""));
        assert!(!android.contains("allow-start-ssh-session"));
    }

    #[test]
    fn mosh_is_explicit_fixed_range_and_desktop_only() {
        let backend = include_str!("lib.rs");
        let frontend = include_str!("../../src/App.tsx");
        let desktop = include_str!("../capabilities/default.json");
        let android = include_str!("../capabilities/android.json");
        assert!(backend.contains("MOSH_UDP_PORT_START: u16 = 60_000"));
        assert!(backend.contains("MOSH_UDP_PORT_END: u16 = 61_000"));
        assert!(backend.contains("--server=mosh-server"));
        assert!(backend.contains("--predict=adaptive"));
        assert!(backend.contains("openssh_policy_arguments(&request.ssh, kex)"));
        assert!(backend.contains("deny_unknown_fields"));
        assert!(!backend.contains("MOSH_KEY"));
        assert!(!backend.contains("println!"));
        assert!(!backend.contains("eprintln!"));
        assert!(frontend.contains("result.engine !== \"mosh\""));
        assert!(frontend.contains("activeSession.engine === \"mosh\""));
        assert!(desktop.contains("allow-start-mosh-session"));
        assert!(!android.contains("allow-start-mosh-session"));
        assert!(!android.contains("start-mosh-session"));
    }

    #[test]
    fn native_forwards_are_bounded_loopback_only_and_android_denied() {
        let native = include_str!("native_engine.rs");
        let frontend = include_str!("../../src/App.tsx");
        let android = include_str!("../capabilities/android.json");
        assert!(native.contains("SocketAddrV4::new(Ipv4Addr::LOCALHOST, bind_port)"));
        assert!(native.contains("MAX_LOCAL_FORWARDS: usize = 8"));
        assert!(native.contains("MAX_LOCAL_FORWARD_CONNECTIONS: usize = 32"));
        assert!(native.contains("MAX_REMOTE_FORWARDS: usize = 8"));
        assert!(native.contains("MAX_REMOTE_FORWARD_CONNECTIONS: usize = 32"));
        assert!(native.contains("MAX_DYNAMIC_FORWARDS: usize = 8"));
        assert!(native.contains("MAX_DYNAMIC_FORWARD_CONNECTIONS: usize = 32"));
        assert!(native.contains("negotiate_socks5_connect(&mut local_stream)"));
        assert!(native.contains("request[1] != 0x01"));
        assert!(native.contains("copy_bidirectional(&mut local_stream, &mut remote_stream)"));
        assert!(frontend.contains("<input value=\"127.0.0.1\" readOnly"));
        assert!(frontend.contains("value=\"SOCKS5 CONNECT\" readOnly"));
        assert!(!frontend.contains("name=\"bindHost\""));
        assert!(!android.contains("native-local-forward"));
        assert!(!android.contains("native-remote-forward"));
        assert!(!android.contains("native-dynamic-forward"));
    }

    #[test]
    fn native_route_measurement_is_bounded_explainable_and_desktop_only() {
        let measurement = include_str!("route_measurement.rs");
        let native = include_str!("native_engine.rs");
        let frontend = include_str!("../../src/components/NetworkToolsDialog.tsx");
        let application = include_str!("../../src/App.tsx");
        let desktop = include_str!("../capabilities/default.json");
        let android = include_str!("../capabilities/android.json");

        assert!(measurement.contains("MAX_CANDIDATES: usize = 4"));
        assert!(measurement.contains("MIN_INTERVAL_SECONDS: u16 = 30"));
        assert!(measurement.contains("MAX_ROUNDS: u16 = 120"));
        assert!(measurement.contains("MIN_SUCCESS_RATE_PERCENT: u8 = 80"));
        assert!(measurement.contains("SWITCH_HYSTERESIS_PERCENT: u64 = 15"));
        assert!(measurement.contains("manager.is_current(campaign_id, generation)"));
        assert!(native.contains("probe_once(validated)"));
        assert!(native.contains("cancellation.cancelled()"));
        assert!(frontend.contains("stop_native_route_measurement"));
        assert!(application.contains("candidateId: \"direct\""));
        assert!(application.contains("candidateId: \"configured-jump\""));
        for command in [
            "start-native-route-measurement",
            "get-native-route-measurement-snapshot",
            "stop-native-route-measurement",
        ] {
            assert!(desktop.contains(command));
            assert!(!android.contains(command));
        }
        for forbidden in [
            "pub host:",
            "pub username:",
            "pub credential_ref:",
            "pub identity_file:",
            "pub password:",
            ".emit(",
            "println!",
            "eprintln!",
        ] {
            assert!(!measurement.contains(forbidden));
        }
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
