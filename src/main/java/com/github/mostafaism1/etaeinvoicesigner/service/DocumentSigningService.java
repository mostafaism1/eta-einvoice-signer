package com.github.mostafaism1.etaeinvoicesigner.service;

public interface DocumentSigningService
                extends CanonicalizationStrategy, SigningStrategy, SignatureMergeStrategy {

        /**
         * Generates a signed document.
         * 
         * @param document a document
         * @return the signed document
         * @throws InvalidDocumentFormatException if the document's format is invalid
         */
        String generateSignedDocument(String document) throws InvalidDocumentFormatException;

}
