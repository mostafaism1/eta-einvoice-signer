package com.github.mostafaism1.etaeinvoicesigner.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

public enum HardwareTokenSecurityFactory implements SecurityFactory {
  INSTANCE;

  private static final String PROVIDER_NAME = "SunPKCS11";
  private static final String KEY_STORE_TYPE = "PKCS11";

  private ConfigurationReader configurationReader;
  private Provider provider;

  private HardwareTokenSecurityFactory() {
    provider = Security.getProvider(PROVIDER_NAME);
    addSecurityProvider();
    configurationReader = FileConfigurationReader.INSTANCE;
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
      KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
      keyStore.load(
        null,
        configurationReader.getKeyStorePassword().toCharArray()
      );
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(
        configurationReader.getCertificateAlias(),
        null
      );
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
      keyStore.load(
        null,
        configurationReader.getKeyStorePassword().toCharArray()
      );
      X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(
        configurationReader.getCertificateAlias()
      );
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
