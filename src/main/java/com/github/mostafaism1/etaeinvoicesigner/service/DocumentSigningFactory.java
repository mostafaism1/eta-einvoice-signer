package com.github.mostafaism1.etaeinvoicesigner.service;

public interface DocumentSigningFactory {

    CanonicalizationStrategy getCanonicalizationStrategy();

    SigningStrategy getSigningStrategy();

    SignatureMergeStrategy getSignatureMergeStrategy();

}
