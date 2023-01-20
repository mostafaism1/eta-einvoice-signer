package com.github.mostafaism1.etaeinvoicesigner.signature;

public interface DocumentSigningFactory {
  CanonicalizationStrategy getCanonicalizationStrategy();

  SigningStrategy getSigningStrategy();

  SignatureMergeStrategy getSignatureMergeStrategy();

  SecurityFactory getSecurityFactory();
}
