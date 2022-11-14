package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public enum FileSecurityFactory implements SecurityFactory {
  INSTANCE;

  private static final String KEY_STORE_TYPE = "PKCS12";
  private ConfigurationReader configurationReader;
  private Provider provider;
  private KeyStore keyStore;
  private String alias;

  private FileSecurityFactory() {
    configurationReader = FileConfigurationReader.INSTANCE;
    provider = new BouncyCastleProvider();
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
    Security.addProvider(provider);
  }

  @Override
  public PrivateKey getPrivateKey() {
    try {
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(
        alias,
        configurationReader.getKeyStorePassword().toCharArray()
      );
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
    try (
      InputStream inputStream = Files.newInputStream(
        Path.of(configurationReader.getPkcs12KeyStoreFilePath())
      )
    ) {
      keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
      keyStore.load(
        inputStream,
        configurationReader.getKeyStorePassword().toCharArray()
      );
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
