package com.github.mostafaism1.etaeinvoicesigner.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.springframework.beans.factory.annotation.Value;

public class PKCS11SecurityFactory implements SecurityFactory {

    private static final String PROVIDER_NAME = "SunPKCS11";
    private static final String KEY_STORE_TYPE = "PKCS11";

    @Value("${pkcs11ConfigFilePath}")
    private String pkcs11ConfigFilePath;
    @Value("${keyStorePassword}")
    private String keyStorePassword;
    @Value("${certificateAlias}")
    private String certificateAlias;

    @Override
    public void addSecurityProvider() {
        Provider provider = Security.getProvider(PROVIDER_NAME);
        provider = provider.configure(pkcs11ConfigFilePath);
        Security.addProvider(provider);
    }

    @Override
    public PrivateKey getPrivateKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null, keyStorePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateAlias, null);
            return privateKey;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    @Override
    public X509Certificate getCertificate() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null, keyStorePassword.toCharArray());
            X509Certificate x509Certificate =
                    (X509Certificate) keyStore.getCertificate(certificateAlias);
            return x509Certificate;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

}
