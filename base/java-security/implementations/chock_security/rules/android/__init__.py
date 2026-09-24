"""The android pack: Android."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="android",
    title="Android",
    covers=(
        "Android apps in Java or Kotlin: WebView, TLS error handling, file modes, components and the AndroidManifest.xml flags that expose them."
    ),
)

RULES: tuple[Rule, ...] = (
)
