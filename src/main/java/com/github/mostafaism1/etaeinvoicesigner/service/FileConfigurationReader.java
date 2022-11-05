package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public enum FileConfigurationReader implements ConfigurationReader {
  INSTANCE;

  Properties properties;

  private FileConfigurationReader() {
    tryReadingConfiguration();
  }

  @Override
  public String getPkcs11ConfigFilePath() {
    return properties.getProperty("keystore.pkcs11ConfigFilePath");
  }

  @Override
  public String getKeyStorePath() {
    return properties.getProperty("keystore.keyStorePath");
  }

  @Override
  public String getKeyStoreType() {
    return properties.getProperty("keystore.keyStoreType");
  }

  @Override
  public String getKeyStorePassword() {
    return properties.getProperty("keystore.keyStorePassword");
  }

  @Override
  public String getCertificateAlias() {
    return properties.getProperty("keystore.certificateAlias");
  }

  private void tryReadingConfiguration() {
    try {
      properties = new Properties();
      String configFilePath = System.getProperty("configFilePath");
      properties.load(new FileInputStream(configFilePath));
    } catch (IOException e) {
      throw new RuntimeException();
    }
  }
}
