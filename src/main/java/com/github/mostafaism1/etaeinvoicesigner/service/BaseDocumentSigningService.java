package com.github.mostafaism1.etaeinvoicesigner.service;

public abstract class BaseDocumentSigningService
  implements DocumentSigningService {
  private DocumentSigningFactory documentSigningFactory;

  protected BaseDocumentSigningService() {
    this.documentSigningFactory = getDocumentSigningFactory();
  }

  @Override
  public String generateSignedDocument(String document) {
    String canonicalizedDocument = documentSigningFactory
      .getCanonicalizationStrategy()
      .canonicalize(document);
    String signature = documentSigningFactory
      .getSigningStrategy()
      .sign(canonicalizedDocument);
    return documentSigningFactory
      .getSignatureMergeStrategy()
      .merge(document, signature);
  }

  protected abstract DocumentSigningFactory getDocumentSigningFactory();
}
