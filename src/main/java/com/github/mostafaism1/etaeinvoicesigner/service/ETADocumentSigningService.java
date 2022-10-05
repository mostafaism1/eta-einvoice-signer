package com.github.mostafaism1.etaeinvoicesigner.service;

import org.springframework.stereotype.Service;

@Service
public class ETADocumentSigningService extends BaseDocumentSigningService {

    @Override
    public String generateSignedDocument(String document) {
        String canonicalizedDocument = super.canonicalize(document);
        String signature = super.sign(canonicalizedDocument);
        return super.merge(document, signature);
    }

    @Override
    protected DocumentSigningFactory getDocumentSigningFactory() {
        return new ETADocumentSigningFactory();
    }

}
