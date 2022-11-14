package com.github.mostafaism1.etaeinvoicesigner.service;

public class ETADocumentSigningFactory implements DocumentSigningFactory {
  ConfigurationReader configurationReader = FileConfigurationReader.INSTANCE;

  @Override
  public CanonicalizationStrategy getCanonicalizationStrategy() {
    return new ETAJsonCanonicalizationStrategy();
  }

  @Override
  public SigningStrategy getSigningStrategy() {
    return new CadesBesSigningStrategy(getSecurityFactory());
  }

  @Override
  public SignatureMergeStrategy getSignatureMergeStrategy() {
    return new ETASignatureMergeStrategy();
  }

  @Override
  public SecurityFactory getSecurityFactory() {
    String keyStoreType = configurationReader.getSignatureKeystoreType();
    if (keyStoreType.equals("hardware")) {
      return HardwareTokenSecurityFactory.INSTANCE;
    } else if (keyStoreType.equals("file")) {
      return FileSecurityFactory.INSTANCE;
    } else {
      throw new InvalidKeyStoreTypeException(keyStoreType);
    }
  }

  private static class InvalidKeyStoreTypeException extends RuntimeException {

    public InvalidKeyStoreTypeException(String keyStoreType) {
      super(
        keyStoreType +
        " is an invalid value for configuration property \"signature.keystore.type\". Allowed values are hardware and file."
      );
    }
  }
}
