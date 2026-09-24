"""The android pack: Android."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.android import android_cleartext_traffic
from chock_security.rules.android import android_exported_component
from chock_security.rules.android import android_manifest_allow_backup
from chock_security.rules.android import android_manifest_debuggable
from chock_security.rules.android import android_ssl_error_ignored
from chock_security.rules.android import android_trust_user_certs
from chock_security.rules.android import android_webview_js_bridge
from chock_security.rules.android import android_world_accessible_file

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
