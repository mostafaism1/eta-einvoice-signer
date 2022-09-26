package com.github.mostafaism1.etaeinvoicesigner.service;

public abstract class AbstractDocumentSigningService implements DocumentSigningService {

    @Override
    public String canonicalize(String document) throws InvalidDocumentFormatException {
        return createCanonicalizationStrategy().canonicalize(document);
    }

    @Override
    public byte[] sign(String data) {
        return createSigningStrategy().sign(data);
    }

    @Override
    public String generateSignedDocument(String document, byte[] signature) {
        return createSignatureMergeStrategy().generateSignedDocument(document, signature);
    }

    protected abstract CanonicalizationStrategy createCanonicalizationStrategy();

    protected abstract SigningStrategy createSigningStrategy();

    protected abstract SignatureMergeStrategy createSignatureMergeStrategy();

}
