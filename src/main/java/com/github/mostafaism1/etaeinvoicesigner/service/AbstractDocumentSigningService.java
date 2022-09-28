package com.github.mostafaism1.etaeinvoicesigner.service;

public abstract class AbstractDocumentSigningService implements DocumentSigningService {

    private DocumentSigningFactory documentSigningFactory;

    protected AbstractDocumentSigningService() {
        this.documentSigningFactory = getDocumentSigningFactory();
    }

    @Override
    public String canonicalize(String document) throws InvalidDocumentFormatException {
        return documentSigningFactory.getCanonicalizationStrategy().canonicalize(document);
    }

    @Override
    public String sign(String data) {
        return documentSigningFactory.getSigningStrategy().sign(data);
    }

    @Override
    public String merge(String document, String signature) {
        return documentSigningFactory.getSignatureMergeStrategy().merge(document, signature);
    }

    protected abstract DocumentSigningFactory getDocumentSigningFactory();

}
