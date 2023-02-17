package com.github.mostafaism1.etaeinvoicesigner.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public enum FileConfigurationReader implements ConfigurationReader {
  INSTANCE;

  private static final String CONFIG_FILE_NAME = "application.properties";
  private final Properties properties;

  private FileConfigurationReader() {
    properties = tryReadConfiguration();
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

  private Properties tryReadConfiguration() {
    try {
      return readConfiguration();
    } catch (IOException e) {
      throw new NoConfigurationFoundException();
    }
  }

  private Properties readConfiguration() throws IOException {
    Properties properties = new Properties();
    InputStream propertiesResource =
        FileConfigurationReader.class.getClassLoader().getResourceAsStream(CONFIG_FILE_NAME);
    properties.load(propertiesResource);
    return properties;
  }

  private static class NoConfigurationFoundException extends RuntimeException {

    public NoConfigurationFoundException() {
      super();
    }
  }
}
