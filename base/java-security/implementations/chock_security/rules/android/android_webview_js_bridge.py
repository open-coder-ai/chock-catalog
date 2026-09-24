"""A JS-enabled WebView that binds a Java object gives any page it loads reflective access to it."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-webview-js-bridge"

_FACTS = facts("android")["webview"]

_BRIDGE_MESSAGE = (
    "This object is bound into a WebView that has JavaScript enabled, so any page the WebView "
    "loads -- including one reached through a redirect it did not choose -- gets reflective "
    "access to every public method on it. Drop the bridge if the page never needs it, or wrap "
    "only the specific methods it must call behind @JavascriptInterface on API 17+ and validate "
    f"every argument as untrusted input. A bridge to a page this app fully controls needs 'chock: "
    f"allow {RULE_ID}' on this line."
)

_FILE_ACCESS_MESSAGE = (
    "This grants file:// pages universal or file-URL access while JavaScript is enabled, so a "
    "page loaded from an attacker-controlled URL can read arbitrary files the app can reach, "
    "including other file:// pages' local storage. Leave these off (the WebView default) and "
    "serve local content through a WebViewAssetLoader/https origin instead. A WebView that only "
    f"ever loads content this app ships needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Both constructs, but only where the same file also turns JavaScript on -- absence of that
    is exactly what makes an otherwise-dangerous call harmless, so it is judged per file."""
    if not text.holds(_FACTS["js_enable"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["js_bridge"] in line:
            yield Finding(RULE_ID, text.path, line_no, line, _BRIDGE_MESSAGE)
        elif any(flag in line for flag in _FACTS["file_url_access"]):
            yield Finding(RULE_ID, text.path, line_no, line, _FILE_ACCESS_MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="WebView JS bridge or file-URL access with JavaScript enabled",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(bind): addJavascriptInterface, or setAllowUniversalAccessFromFileURLs|"
        "setAllowFileAccessFromFileURLs|setAllowFileAccess(true), where the same file's WebView "
        "also has setJavaScriptEnabled(true) -- drop the bridge, or scope file access off"
    ),
    refuses="`addJavascriptInterface(` or a file-URL-access setter turned on, in a file where JS is enabled",
    silent_on="either call in a file that never enables JavaScript; a WebView with JS left off",
)
