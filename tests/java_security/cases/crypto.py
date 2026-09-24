"""Cases for the crypto pack: Cryptography and TLS.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

WEAK_CIPHER = "crypto-weak-cipher"
WEAK_PASSWORD_HASH = "crypto-weak-password-hash"
INSECURE_RANDOM = "crypto-insecure-random"
TLS_TRUST_ALL = "crypto-tls-trust-all"
LEGACY_TLS = "crypto-legacy-tls"
STATIC_IV_OR_SALT = "crypto-static-iv-or-salt"
SHORT_KEY = "crypto-short-key"
HARDCODED_CREDENTIAL = "crypto-hardcoded-credential"
SECURERANDOM_FIXED_SEED = "crypto-securerandom-fixed-seed"
WEAK_SIGNATURE_ALGORITHM = "crypto-weak-signature-algorithm"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # crypto-weak-cipher
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n', [1]),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n', [1]),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("RC4");\n', [1]),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n', [1]),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("AES");\n', [1]),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n', []),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("ChaCha20-Poly1305");\n', []),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n', []),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\n', []),
    (WEAK_CIPHER, "C.java", 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n', []),
    # crypto-weak-password-hash
    (
        WEAK_PASSWORD_HASH,
        "C.java",
        'MessageDigest md = MessageDigest.getInstance("MD5"); md.update(password.getBytes());\n',
        [1],
    ),
    (
        WEAK_PASSWORD_HASH,
        "C.java",
        'public byte[] hashPassword(String password) {\n  MessageDigest md = MessageDigest.getInstance("SHA-256");\n  return md.digest(password.getBytes());\n}\n',
        [2],
    ),
    (WEAK_PASSWORD_HASH, "C.java", "String hex = DigestUtils.md5Hex(password);\n", [1]),
    (
        WEAK_PASSWORD_HASH,
        "C.java",
        'MessageDigest md = MessageDigest.getInstance("MD5"); md.update(file.getBytes());\n',
        [],
    ),
    (WEAK_PASSWORD_HASH, "C.java", "String etag = DigestUtils.md5Hex(responseBody);\n", []),
    (WEAK_PASSWORD_HASH, "C.java", "String hash = BCrypt.hashpw(password, BCrypt.gensalt());\n", []),
    (WEAK_PASSWORD_HASH, "C.java", "byte[] hash = Argon2Factory.create().hash(10, 65536, password);\n", []),
    (
        WEAK_PASSWORD_HASH,
        "C.java",
        'void a() {\n  log.info("Password changed for user {}", user.getId());\n'
        '  MessageDigest md = MessageDigest.getInstance("SHA-256");\n  byte[] checksum = md.digest(fileBytes);\n}\n',
        [],
    ),
    # crypto-insecure-random
    (INSECURE_RANDOM, "C.java", 'String token = new Random().nextInt() + "";\n', [1]),
    (
        INSECURE_RANDOM,
        "C.java",
        "public String generateResetCode() {\n  return String.valueOf(new Random().nextInt(999999));\n}\n",
        [2],
    ),
    (INSECURE_RANDOM, "C.java", "String apiKey = RandomStringUtils.randomAlphanumeric(32);\n", [1]),
    (INSECURE_RANDOM, "C.java", "String sessionId = Long.toHexString(ThreadLocalRandom.current().nextLong());\n", [1]),
    (INSECURE_RANDOM, "C.java", "int shuffleIndex = new Random().nextInt(deck.size());\n", []),
    (INSECURE_RANDOM, "C.java", "int delay = new Random().nextInt(1000);\n", []),
    (INSECURE_RANDOM, "C.java", 'String sessionTimeoutLabel = "30m";\n', []),
    (INSECURE_RANDOM, "C.java", "Collections.shuffle(deck, new Random());\n", []),
    (INSECURE_RANDOM, "C.java", "String token = new SecureRandom().generateSeed(16).toString();\n", []),
    (INSECURE_RANDOM, "C.java", "byte[] key = new byte[32];\nnew SecureRandom().nextBytes(key);\n", []),
    # crypto-tls-trust-all
    (
        TLS_TRUST_ALL,
        "C.java",
        "class X implements X509TrustManager {\n"
        "  public void checkServerTrusted(X509Certificate[] c, String a) {\n"
        "  }\n"
        "  public void checkClientTrusted(X509Certificate[] c, String a) {}\n"
        "  public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "}\n",
        [3, 4],
    ),
    (TLS_TRUST_ALL, "C.java", "HostnameVerifier hv = (h, s) -> true;\n", [1]),
    (TLS_TRUST_ALL, "C.java", "builder.hostnameVerifier(NoopHostnameVerifier.INSTANCE);\n", [1]),
    (TLS_TRUST_ALL, "C.java", "TrustManagerFactory tmf = InsecureTrustManagerFactory.INSTANCE;\n", [1]),
    (
        TLS_TRUST_ALL,
        "C.java",
        "verifier.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);\n",
        [1],
    ),
    (
        TLS_TRUST_ALL,
        "C.java",
        "class X implements X509TrustManager {\n"
        "  public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {\n"
        "    delegate.checkServerTrusted(c, a);\n"
        "  }\n"
        "  public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }\n"
        "}\n",
        [],
    ),
    (
        TLS_TRUST_ALL,
        "C.java",
        "class X implements HostnameVerifier {\n"
        "  public boolean verify(String host, SSLSession session) {\n"
        "    return HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session);\n"
        "  }\n"
        "}\n",
        [],
    ),
    # crypto-legacy-tls
    (LEGACY_TLS, "C.java", 'SSLContext ctx = SSLContext.getInstance("TLSv1");\n', [1]),
    (LEGACY_TLS, "C.java", 'SSLContext ctx = SSLContext.getInstance("SSLv3");\n', [1]),
    (LEGACY_TLS, "C.java", 'socket.setEnabledProtocols(new String[]{"TLSv1.1"});\n', [1]),
    (LEGACY_TLS, "app.properties", "server.ssl.enabled-protocols=SSLv3,TLSv1\n", [1]),
    (LEGACY_TLS, "C.java", 'System.setProperty("https.protocols", "TLSv1,TLSv1.1");\n', [1]),
    (LEGACY_TLS, "C.java", 'SSLContext ctx = SSLContext.getInstance("TLS");\n', []),
    (LEGACY_TLS, "app.properties", "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3\n", []),
    (LEGACY_TLS, "C.java", 'socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});\n', []),
    # crypto-static-iv-or-salt
    (STATIC_IV_OR_SALT, "C.java", 'IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());\n', [1]),
    (
        STATIC_IV_OR_SALT,
        "C.java",
        "GCMParameterSpec spec = new GCMParameterSpec(128, new byte[]{1,2,3,4,5,6,7,8,9,10,11,12});\n",
        [1],
    ),
    (
        STATIC_IV_OR_SALT,
        "C.java",
        "public void enc() {\n  byte[] iv = new byte[16];\n  cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));\n}\n",
        [3],
    ),
    (
        STATIC_IV_OR_SALT,
        "C.java",
        "public void enc() {\n  byte[] iv = new byte[16];\n  new SecureRandom().nextBytes(iv);\n  cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));\n}\n",
        [],
    ),
    (
        STATIC_IV_OR_SALT,
        "C.java",
        "public void enc() {\n  byte[] iv = new byte[12];\n  random.nextBytes(iv);\n  cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));\n}\n",
        [],
    ),
    # crypto-short-key
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n  g.initialize(1024);\n}\n',
        [3],
    ),
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\n  g.initialize(160);\n}\n',
        [3],
    ),
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyGenerator g = KeyGenerator.getInstance("AES");\n  g.init(64);\n}\n',
        [3],
    ),
    (SHORT_KEY, "C.java", "PBEKeySpec spec = new PBEKeySpec(pwd, salt, 1000, 256);\n", [1]),
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n  g.initialize(2048);\n}\n',
        [],
    ),
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyGenerator g = KeyGenerator.getInstance("AES");\n  g.init(256);\n}\n',
        [],
    ),
    (SHORT_KEY, "C.java", "PBEKeySpec spec = new PBEKeySpec(pwd, salt, 210000, 256);\n", []),
    (
        SHORT_KEY,
        "C.java",
        'public void gen() throws Exception {\n  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n  g.initialize(keySize);\n}\n',
        [],
    ),
    # crypto-hardcoded-credential
    (HARDCODED_CREDENTIAL, "C.java", 'Connection c = DriverManager.getConnection(url, "admin", "s3cr3t");\n', [1]),
    (HARDCODED_CREDENTIAL, "C.java", 'var auth = new PasswordAuthentication(user, "s3cr3t".toCharArray());\n', [1]),
    (HARDCODED_CREDENTIAL, "C.java", 'ds.setPassword("s3cr3t");\n', [1]),
    (
        HARDCODED_CREDENTIAL,
        "C.java",
        'SecretKeySpec key = new SecretKeySpec("s3cr3tkeybytes16".getBytes(), "AES");\n',
        [1],
    ),
    (HARDCODED_CREDENTIAL, "C.java", 'Algorithm alg = Algorithm.HMAC256("s3cr3t");\n', [1]),
    (HARDCODED_CREDENTIAL, "C.java", 'Connection c = DriverManager.getConnection(url, "admin", pass);\n', []),
    (HARDCODED_CREDENTIAL, "C.java", 'ds.setPassword(System.getenv("DB_PASSWORD"));\n', []),
    (HARDCODED_CREDENTIAL, "C.java", 'ds.setPassword("");\n', []),
    (
        HARDCODED_CREDENTIAL,
        "src/test/java/C.java",
        'Connection c = DriverManager.getConnection(url, "admin", "s3cr3t");\n',
        [],
    ),
    # crypto-securerandom-fixed-seed
    (
        SECURERANDOM_FIXED_SEED,
        "C.java",
        "SecureRandom random = new SecureRandom();\nrandom.setSeed(1234L);\n",
        [2],
    ),
    (
        SECURERANDOM_FIXED_SEED,
        "C.java",
        'SecureRandom random = new SecureRandom();\nrandom.setSeed("fixed-seed".getBytes());\n',
        [2],
    ),
    (
        SECURERANDOM_FIXED_SEED,
        "C.java",
        "SecureRandom random = new SecureRandom();\nrandom.setSeed(SEED_CONSTANT);\n",
        [2],
    ),
    (SECURERANDOM_FIXED_SEED, "C.java", "SecureRandom random = new SecureRandom();\n", []),
    (
        SECURERANDOM_FIXED_SEED,
        "C.java",
        "Random random = new Random();\nrandom.setSeed(1234L);\n",
        [],
    ),
    (
        SECURERANDOM_FIXED_SEED,
        "C.java",
        "SecureRandom random = new SecureRandom();\nrandom.setSeed(entropy);\n",
        [],
    ),
    # crypto-weak-signature-algorithm
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Signature sig = Signature.getInstance("MD5withRSA");\n', [1]),
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Signature sig = Signature.getInstance("SHA1withRSA");\n', [1]),
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Signature sig = Signature.getInstance("SHA1withDSA");\n', [1]),
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Signature sig = Signature.getInstance("SHA256withRSA");\n', []),
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Signature sig = Signature.getInstance("SHA256withECDSA");\n', []),
    (WEAK_SIGNATURE_ALGORITHM, "C.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n', []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
