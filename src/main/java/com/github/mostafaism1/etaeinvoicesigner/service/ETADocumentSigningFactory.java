package com.github.mostafaism1.etaeinvoicesigner.service;

public class ETADocumentSigningFactory implements DocumentSigningFactory {

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
    return HardwareTokenSecurityFactory.INSTANCE;
  }
}
