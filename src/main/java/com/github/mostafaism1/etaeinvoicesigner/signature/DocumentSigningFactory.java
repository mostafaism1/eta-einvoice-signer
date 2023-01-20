package com.github.mostafaism1.etaeinvoicesigner.signature;

import com.github.mostafaism1.etaeinvoicesigner.signature.canonicalization.CanonicalizationStrategy;
import com.github.mostafaism1.etaeinvoicesigner.signature.merge.SignatureMergeStrategy;
import com.github.mostafaism1.etaeinvoicesigner.signature.security.SecurityFactory;

public interface DocumentSigningFactory {
  CanonicalizationStrategy getCanonicalizationStrategy();

  SigningStrategy getSigningStrategy();

  SignatureMergeStrategy getSignatureMergeStrategy();

  SecurityFactory getSecurityFactory();
}
