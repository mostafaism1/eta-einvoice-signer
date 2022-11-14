package com.github.mostafaism1.etaeinvoicesigner.service;

public interface ConfigurationReader {
  public String getSignatureKeystoreType();

  public String getPkcs11ConfigFilePath();

  public String getPkcs12KeyStoreFilePath();

  public String getKeyStorePassword();

  public String getCertificateIssuerName();

  public String getUserName();

  public String getEncryptedPassword();
}
