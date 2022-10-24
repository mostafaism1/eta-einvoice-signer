package com.github.mostafaism1.etaeinvoicesigner.service;

import org.springframework.stereotype.Service;

@Service
public class ETADocumentSigningService extends BaseDocumentSigningService {

  @Override
  protected DocumentSigningFactory getDocumentSigningFactory() {
    return new ETADocumentSigningFactory();
  }
}
