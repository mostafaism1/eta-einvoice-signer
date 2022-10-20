package com.github.mostafaism1.etaeinvoicesigner.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

public enum SunPKCS11SecurityFactory implements SecurityFactory {

    INSTANCE;

    private static final String PROVIDER_NAME = "SunPKCS11";
    private static final String KEY_STORE_TYPE = "PKCS11";

    private final String pkcs11ConfigFilePath = "C:\\workspace\\eta-einvoice-signer\\pkcs11.cfg";
    private final String keyStorePassword = "42131536";
    private final String certificateAlias = "0x04c8978a8578c3f05d028ea8d6dac515f4092da4";

    private Provider provider;

    private SunPKCS11SecurityFactory() {
        provider = Security.getProvider(PROVIDER_NAME);
        addSecurityProvider();
    }

    @Override
    public void addSecurityProvider() {
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

    @Override
    public Provider getProvider() {
        return provider;
    }

}
