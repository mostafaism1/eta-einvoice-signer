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

public class FileSecurityFactory implements SecurityFactory {
  private ConfigurationReader configurationReader;
  private Provider provider;

  public FileSecurityFactory() {
    configurationReader = FileConfigurationReader.INSTANCE;
    provider = new BouncyCastleProvider();
    addSecurityProvider();
  }

  @Override
  public void addSecurityProvider() {
    Security.addProvider(provider);
  }

  @Override
  public PrivateKey getPrivateKey() {
    try {
      InputStream inputStream = Files.newInputStream(
        Path.of(configurationReader.getKeyStorePath())
      );
      KeyStore keyStore = KeyStore.getInstance(
        configurationReader.getKeyStoreType()
      );
      keyStore.load(
        inputStream,
        configurationReader.getKeyStorePassword().toCharArray()
      );
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(
        configurationReader.getCertificateAlias(),
        configurationReader.getKeyStorePassword().toCharArray()
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
      InputStream inputStream = Files.newInputStream(
        Path.of(configurationReader.getKeyStorePath())
      );
      KeyStore keyStore = KeyStore.getInstance(
        configurationReader.getKeyStoreType()
      );
      keyStore.load(
        inputStream,
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
