package com.acme.crypto;

import javax.crypto.Cipher;
import java.security.SecureRandom;

public class CryptoService {
    private final SecureRandom random = new SecureRandom();
    private final SecretKey key;

    public byte[] encrypt(byte[] plain) throws Exception {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(plain);
    }

    public String newApiToken() {
        byte[] b = new byte[32];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public List<String> sample(List<String> items) {
        List<String> copy = new ArrayList<>(items);
        Collections.shuffle(copy, new Random(42));
        return copy.subList(0, 3);
    }

    public KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        return g.generateKeyPair();
    }

    public SSLContext tls() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, null, null);
        return ctx;
    }
}
