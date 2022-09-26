package com.github.mostafaism1.etaeinvoicesigner.service;

public abstract class AbstractDocumentSigningService implements DocumentSigningService {

    private DocumentSigningFactory documentSigningFactory;

    protected AbstractDocumentSigningService(DocumentSigningFactory documentSigningFactory) {
        this.documentSigningFactory = documentSigningFactory;
    }

    @Override
    public String canonicalize(String document) throws InvalidDocumentFormatException {
        return documentSigningFactory.getCanonicalizationStrategy().canonicalize(document);
    }

    @Override
    public byte[] sign(String data) {
        return documentSigningFactory.getSigningStrategy().sign(data);
    }

    @Override
    public String generateSignedDocument(String document, byte[] signature) {
        return documentSigningFactory.getSignatureMergeStrategy()
                .generateSignedDocument(document, signature);
    }

}
