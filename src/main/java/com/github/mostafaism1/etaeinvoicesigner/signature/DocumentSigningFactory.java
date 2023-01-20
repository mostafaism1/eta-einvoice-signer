package com.github.mostafaism1.etaeinvoicesigner.signature;

import com.github.mostafaism1.etaeinvoicesigner.signature.canonicalization.CanonicalizationStrategy;

public interface DocumentSigningFactory {
  CanonicalizationStrategy getCanonicalizationStrategy();

  SigningStrategy getSigningStrategy();

  SignatureMergeStrategy getSignatureMergeStrategy();

  SecurityFactory getSecurityFactory();
}
