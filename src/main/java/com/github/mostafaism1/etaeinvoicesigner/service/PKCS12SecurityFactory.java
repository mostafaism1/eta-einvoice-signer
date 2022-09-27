package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PKCS12SecurityFactory implements SecurityFactory {

    @Override
    public void addSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public PrivateKey getPrivateKey() {
        try {
            InputStream inputStream = Files.newInputStream(Path.of("signer-key-store.p12"));
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, "password".toCharArray());
            PrivateKey privateKey =
                    (PrivateKey) keyStore.getKey("signer-cert-alias", "password".toCharArray());
            return privateKey;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    @Override
    public X509Certificate getCertificate() {
        try {
            InputStream inputStream = Files.newInputStream(Path.of("signer-key-store.p12"));
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, "password".toCharArray());
            X509Certificate x509Certificate =
                    (X509Certificate) keyStore.getCertificate("signer-cert-alias");
            return x509Certificate;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

}
