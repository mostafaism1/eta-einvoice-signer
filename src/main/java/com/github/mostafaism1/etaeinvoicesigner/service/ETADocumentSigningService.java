package com.github.mostafaism1.etaeinvoicesigner.service;

import org.springframework.stereotype.Service;

@Service
public class ETADocumentSigningService extends AbstractDocumentSigningService {

    public ETADocumentSigningService(DocumentSigningFactory documentSigningFactory) {
        super(new ETADocumentSigningFactory());
    }

    @Override
    public String generateSignedDocument(String document) {
        String canonicalizedDocument = super.canonicalize(document);
        String signature = super.sign(canonicalizedDocument);
        return super.merge(canonicalizedDocument, signature);
    }

}
