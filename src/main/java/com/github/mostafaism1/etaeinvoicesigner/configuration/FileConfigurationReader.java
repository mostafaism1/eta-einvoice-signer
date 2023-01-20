package com.github.mostafaism1.etaeinvoicesigner.configuration;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public enum FileConfigurationReader implements ConfigurationReader {
  INSTANCE;

  Properties defaultProperties;
  Properties properties;

  private FileConfigurationReader() {
    tryReadingConfiguration();
  }

  @Override
  public String getSignatureKeystoreType() {
    return properties.getProperty("signature.keystore.type");
  }

  @Override
  public String getPkcs11ConfigFilePath() {
    return properties.getProperty("signature.keystore.pkcs11ConfigFilePath");
  }

  @Override
  public String getPkcs12KeyStoreFilePath() {
    return properties.getProperty("signature.keystore.pkcs12KeyStoreFilePath");
  }

  @Override
  public String getKeyStorePassword() {
    return properties.getProperty("signature.keystore.password");
  }

  @Override
  public String getCertificateIssuerName() {
    return properties.getProperty("signature.keystore.certificateIssuerName");
  }

  @Override
  public String getUserName() {
    return properties.getProperty("auth.user.userName");
  }

  @Override
  public String getEncryptedPassword() {
    return properties.getProperty("auth.user.encryptedPassword");
  }

  private void tryReadingConfiguration() {
    boolean defaultConfigReadSuccessfully = true;
    try {
      tryReadingDefaultConfiguration();
    } catch (Exception e) {
      defaultConfigReadSuccessfully = false;
    }
    try {
      tryReadingUserConfiguration();
    } catch (Exception e) {
      if (!defaultConfigReadSuccessfully) {
        throw new NoConfigurationFoundException();
      }
    }
  }

  private void tryReadingDefaultConfiguration() throws IOException {
    defaultProperties = new Properties();
    defaultProperties.load(
      FileConfigurationReader.class.getClassLoader()
        .getResourceAsStream("application.properties")
    );
  }

  private void tryReadingUserConfiguration() throws IOException {
    properties = new Properties(defaultProperties);
    String configFilePath = System.getProperty("configFilePath");
    properties.load(new FileInputStream(configFilePath));
  }

  private static class NoConfigurationFoundException extends RuntimeException {

    public NoConfigurationFoundException() {
      super();
    }
  }
}
