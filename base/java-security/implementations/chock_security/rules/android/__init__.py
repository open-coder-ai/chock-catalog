"""The android pack: Android."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.android import (
    android_cleartext_traffic,
    android_exported_component,
    android_manifest_allow_backup,
    android_manifest_debuggable,
    android_ssl_error_ignored,
    android_trust_user_certs,
    android_webview_js_bridge,
    android_world_accessible_file,
)

PACK = Pack(
    id="android",
    title="Android",
    covers=(
        "Android apps in Java or Kotlin: WebView, TLS error handling, file modes, components and the AndroidManifest.xml flags that expose them."
    ),
)

RULES: tuple[Rule, ...] = (
    android_webview_js_bridge.RULE,
    android_ssl_error_ignored.RULE,
    android_world_accessible_file.RULE,
    android_manifest_debuggable.RULE,
    android_manifest_allow_backup.RULE,
    android_cleartext_traffic.RULE,
    android_trust_user_certs.RULE,
    android_exported_component.RULE,
)
