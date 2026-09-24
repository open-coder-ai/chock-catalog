"""Cases for the android pack: Android.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

BRIDGE = "android-webview-js-bridge"
SSL = "android-ssl-error-ignored"
WORLD = "android-world-accessible-file"
DEBUGGABLE = "android-manifest-debuggable"
BACKUP = "android-manifest-allow-backup"
CLEARTEXT = "android-cleartext-traffic"
TRUST_USER = "android-trust-user-certs"
EXPORTED = "android-exported-component"

MANIFEST_HEAD = (
    '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
)
MANIFEST_TAIL = "</manifest>\n"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # --- android-webview-js-bridge ------------------------------------------------------------
    (
        BRIDGE,
        "MainActivity.java",
        "webView.getSettings().setJavaScriptEnabled(true);\n"
        'webView.addJavascriptInterface(new JsBridge(), "Android");\n',
        [2],
    ),
    (
        BRIDGE,
        "MainActivity.kt",
        "webView.settings.javaScriptEnabled = true\n"
        "webView.settings.setJavaScriptEnabled(true)\n"
        "webView.settings.setAllowUniversalAccessFromFileURLs(true)\n",
        [3],
    ),
    (BRIDGE, "MainActivity.java", 'webView.addJavascriptInterface(new JsBridge(), "Android");\n', []),
    (
        BRIDGE,
        "MainActivity.java",
        "webView.getSettings().setJavaScriptEnabled(false);\n"
        'webView.addJavascriptInterface(new JsBridge(), "Android");\n',
        [],
    ),
    (BRIDGE, "MainActivity.java", "webView.getSettings().setJavaScriptEnabled(true);\nanalytics.recordEvent();\n", []),
    # --- android-ssl-error-ignored --------------------------------------------------------------
    (
        SSL,
        "InsecureClient.java",
        "public class InsecureClient extends WebViewClient {\n"
        "  @Override\n"
        "  public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {\n"
        "    handler.proceed();\n"
        "  }\n}\n",
        [4],
    ),
    (
        SSL,
        "InsecureClient.kt",
        "class InsecureClient : WebViewClient() {\n"
        "    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {\n"
        "        handler?.proceed()\n"
        "    }\n}\n",
        [3],
    ),
    (
        SSL,
        "SafeClient.java",
        "public class SafeClient extends WebViewClient {\n"
        "  @Override\n"
        "  public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {\n"
        "    handler.cancel();\n"
        "  }\n}\n",
        [],
    ),
    (SSL, "Plain.java", 'public class Plain {\n  public void connect() {\n    System.out.println("ok");\n  }\n}\n', []),
    # --- android-world-accessible-file -----------------------------------------------------------
    (WORLD, "Prefs.java", 'SharedPreferences p = getSharedPreferences("app", Context.MODE_WORLD_READABLE);\n', [1]),
    (WORLD, "Store.java", 'FileOutputStream out = openFileOutput("data", Context.MODE_WORLD_WRITEABLE);\n', [1]),
    (WORLD, "Store.java", "file.setReadable(true, false);\n", [1]),
    (WORLD, "Prefs.java", 'SharedPreferences p = getSharedPreferences("app", Context.MODE_PRIVATE);\n', []),
    (WORLD, "Store.java", "file.setReadable(true, true);\n", []),
    (WORLD, "Store.java", "file.setReadable(true);\n", []),
    # --- android-manifest-debuggable -------------------------------------------------------------
    (
        DEBUGGABLE,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:debuggable="true">\n  </application>\n' + MANIFEST_TAIL,
        [3],
    ),
    (
        DEBUGGABLE,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:debuggable="false">\n  </application>\n' + MANIFEST_TAIL,
        [],
    ),
    (DEBUGGABLE, "AndroidManifest.xml", MANIFEST_HEAD + "  <application>\n  </application>\n" + MANIFEST_TAIL, []),
    (
        DEBUGGABLE,
        "src/debug/AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:debuggable="true">\n  </application>\n' + MANIFEST_TAIL,
        [],
    ),
    # --- android-manifest-allow-backup -------------------------------------------------------------
    (
        BACKUP,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:allowBackup="true">\n  </application>\n' + MANIFEST_TAIL,
        [3],
    ),
    (
        BACKUP,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:allowBackup="false">\n  </application>\n' + MANIFEST_TAIL,
        [],
    ),
    (
        BACKUP,
        "AndroidManifest.xml",
        MANIFEST_HEAD
        + '  <application android:allowBackup="true" android:fullBackupContent="@xml/backup_rules">\n  </application>\n'
        + MANIFEST_TAIL,
        [],
    ),
    # --- android-cleartext-traffic -------------------------------------------------------------
    (
        CLEARTEXT,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:usesCleartextTraffic="true">\n  </application>\n' + MANIFEST_TAIL,
        [3],
    ),
    (
        CLEARTEXT,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application android:usesCleartextTraffic="false">\n  </application>\n' + MANIFEST_TAIL,
        [],
    ),
    (
        CLEARTEXT,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <base-config cleartextTrafficPermitted="true">\n  </base-config>\n</network-security-config>\n',
        [3],
    ),
    (
        CLEARTEXT,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <domain-config cleartextTrafficPermitted="true">\n    <domain includeSubdomains="false">10.0.2.2</domain>\n'
        "  </domain-config>\n</network-security-config>\n",
        [],
    ),
    (
        CLEARTEXT,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <base-config cleartextTrafficPermitted="false">\n  </base-config>\n</network-security-config>\n',
        [],
    ),
    # --- android-trust-user-certs -------------------------------------------------------------
    (
        TRUST_USER,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <base-config>\n    <trust-anchors>\n      <certificates src="user" />\n'
        "    </trust-anchors>\n  </base-config>\n</network-security-config>\n",
        [5],
    ),
    (
        TRUST_USER,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <domain-config>\n    <domain includeSubdomains="false">10.0.2.2</domain>\n'
        '    <trust-anchors>\n      <certificates src="user" />\n'
        "    </trust-anchors>\n  </domain-config>\n</network-security-config>\n",
        [],
    ),
    (
        TRUST_USER,
        "network_security_config.xml",
        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
        '  <base-config>\n    <trust-anchors>\n      <certificates src="system" />\n'
        "    </trust-anchors>\n  </base-config>\n</network-security-config>\n",
        [],
    ),
    # --- android-exported-component -------------------------------------------------------------
    (
        EXPORTED,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application>\n    <receiver android:name=".BootReceiver" android:exported="true">\n'
        "    </receiver>\n  </application>\n" + MANIFEST_TAIL,
        [4],
    ),
    (
        EXPORTED,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application>\n    <service android:name=".SyncService" android:exported="true" '
        'android:permission="com.example.PERMISSION_SYNC">\n    </service>\n  </application>\n' + MANIFEST_TAIL,
        [],
    ),
    (
        EXPORTED,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application>\n    <activity android:name=".MainActivity" android:exported="true">\n'
        '      <intent-filter>\n        <action android:name="android.intent.action.MAIN" />\n'
        '        <category android:name="android.intent.category.LAUNCHER" />\n'
        "      </intent-filter>\n    </activity>\n  </application>\n" + MANIFEST_TAIL,
        [],
    ),
    (
        EXPORTED,
        "AndroidManifest.xml",
        MANIFEST_HEAD + '  <application>\n    <provider android:name=".DataProvider" android:exported="false">\n'
        "    </provider>\n  </application>\n" + MANIFEST_TAIL,
        [],
    ),
    (
        EXPORTED,
        "AndroidManifest.xml",
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '  <application><activity android:exported="true"</application>\n</manifest>\n',
        [],
    ),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
