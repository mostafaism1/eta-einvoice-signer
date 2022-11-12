package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public enum FileSecurityFactory implements SecurityFactory {
  INSTANCE;

  private ConfigurationReader configurationReader;
  private Provider provider;
  private KeyStore keyStore;

  private FileSecurityFactory() {
    configurationReader = FileConfigurationReader.INSTANCE;
    provider = new BouncyCastleProvider();
    addSecurityProvider();
    initializeKeystore();
  }

  @Override
  public void addSecurityProvider() {
    Security.addProvider(provider);
  }

  @Override
  public PrivateKey getPrivateKey() {
    try {
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(
        configurationReader.getCertificateAlias(),
        configurationReader.getKeyStorePassword().toCharArray()
      );
      return privateKey;
    } catch (
      UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e
    ) {
      throw new RuntimeException();
    }
  }

  @Override
  public X509Certificate getCertificate() {
    try {
      X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(
        configurationReader.getCertificateAlias()
      );
      return x509Certificate;
    } catch (Exception e) {
      throw new RuntimeException();
    }
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  private void initializeKeystore() {
    try (
      InputStream inputStream = Files.newInputStream(
        Path.of(configurationReader.getKeyStorePath())
      )
    ) {
      keyStore = KeyStore.getInstance(configurationReader.getKeyStoreType());
      keyStore.load(
        inputStream,
        configurationReader.getKeyStorePassword().toCharArray()
      );
    } catch (
      KeyStoreException
      | NoSuchAlgorithmException
      | CertificateException
      | IOException e
    ) {
      throw new RuntimeException();
    }
  }
}
