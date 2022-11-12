package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
    boolean defaultConfigReadSuccessfully = true;
    try {
      tryReadingDefaultConfiguration();
    } catch (IOException e1) {
      defaultConfigReadSuccessfully = false;
    }
    try {
      tryReadingUserConfiguration();
    } catch (Exception e1) {
      if (!defaultConfigReadSuccessfully) {
        throw new RuntimeException();
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

  private void tryReadingUserConfiguration()
    throws FileNotFoundException, IOException {
    properties = new Properties(defaultProperties);
    String configFilePath = System.getProperty("configFilePath");
    properties.load(new FileInputStream(configFilePath));
  }
}
