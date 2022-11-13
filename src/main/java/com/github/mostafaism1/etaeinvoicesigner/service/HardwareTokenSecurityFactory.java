package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public enum HardwareTokenSecurityFactory implements SecurityFactory {
  INSTANCE;

  private static final String PROVIDER_NAME = "SunPKCS11";
  private static final String KEY_STORE_TYPE = "PKCS11";

  private ConfigurationReader configurationReader;
  private Provider provider;
  private KeyStore keyStore;
  private String alias;

  private HardwareTokenSecurityFactory() {
    configurationReader = FileConfigurationReader.INSTANCE;
    provider = Security.getProvider(PROVIDER_NAME);
    addSecurityProvider();
    initializeKeystore();
    alias =
      SecurityUtils.getAliasByCertificateIssuerName(
        keyStore,
        configurationReader.getCertificateIssuerName()
      );
  }

  @Override
  public void addSecurityProvider() {
    provider =
      provider.configure(configurationReader.getPkcs11ConfigFilePath());
    Security.addProvider(provider);
  }

  @Override
  public PrivateKey getPrivateKey() {
    try {
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
      return privateKey;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public X509Certificate getCertificate() {
    try {
      X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(
        alias
      );
      return x509Certificate;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  private void initializeKeystore() {
    try {
      keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
      keyStore.load(
        null,
        configurationReader.getKeyStorePassword().toCharArray()
      );
    } catch (
      KeyStoreException
      | NoSuchAlgorithmException
      | CertificateException
      | IOException e
    ) {
      throw new RuntimeException(e);
    }
  }
}
