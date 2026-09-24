"""Extra coverage cases for the crypto pack, kept separate from crypto.py to avoid merge
conflicts with the parallel work adding new rules to this pack.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

TLS_TRUST_ALL = "crypto-tls-trust-all"
LEGACY_TLS = "crypto-legacy-tls"
STATIC_IV_OR_SALT = "crypto-static-iv-or-salt"
SHORT_KEY = "crypto-short-key"
WEAK_PASSWORD_HASH = "crypto-weak-password-hash"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # crypto-legacy-tls: setProperty() naming a key this rule does not track stays silent
    (LEGACY_TLS, "C.java", 'System.setProperty("os.name", "Linux");\n', []),
    # crypto-static-iv-or-salt: a literal salt fed straight into PBEKeySpec (neither IV nor GCM)
    (
        STATIC_IV_OR_SALT,
        "C.java",
        'PBEKeySpec spec = new PBEKeySpec(password, "static-salt".getBytes(), 10000, 256);\n',
        [1],
    ),
    # crypto-short-key: an algorithm this rule does not track (Ed25519/XDH-style curves) stays silent
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");\n  g.initialize(255);\n}\n',
        [],
    ),
    # crypto-short-key: .initialize() on a variable never assigned by getInstance() in this method
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n  other.initialize(512);\n}\n',
        [],
    ),
    # crypto-tls-trust-all: an interface's own abstract declaration is not an override to inspect
    (
        TLS_TRUST_ALL,
        "C.java",
        "public interface CustomTrustManager extends X509TrustManager {\n"
        "  void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException;\n"
        "}\n",
        [],
    ),
    # crypto-tls-trust-all: a signature split across lines, with the brace on its own line
    (
        TLS_TRUST_ALL,
        "C.java",
        "class X implements X509TrustManager {\n"
        "  public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
        "      throws CertificateException {\n"
        "  }\n}\n",
        [4],
    ),
    # crypto-tls-trust-all: a body whose closing brace never arrives (a file cut off mid-edit)
    (
        TLS_TRUST_ALL,
        "C.java",
        "public class BadTrustManager implements X509TrustManager {\n"
        "    public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
        '        System.out.println("trusting");\n',
        [],
    ),
    # crypto-tls-trust-all: a declared verify() override (not a lambda) that always returns true
    (
        TLS_TRUST_ALL,
        "C.java",
        "class X implements HostnameVerifier {\n"
        "  public boolean verify(String host, SSLSession session) {\n"
        "    return true;\n"
        "  }\n}\n",
        [4],
    ),
    # crypto-weak-password-hash: a DigestUtils hex form this rule does not track stays silent
    (WEAK_PASSWORD_HASH, "C.java", "String hex = DigestUtils.sha512Hex(password);\n", []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
