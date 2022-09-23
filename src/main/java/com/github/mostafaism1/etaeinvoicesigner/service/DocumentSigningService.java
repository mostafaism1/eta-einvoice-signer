package com.github.mostafaism1.etaeinvoicesigner.service;

public interface DocumentSigningService {

    /**
     * Transforms a valid document to a canonical format.
     * 
     * @param document a valid document
     * @return the canonical document
     * @throws InvalidDocumentFormatException if document is an invalid json
     */
    String canonicalize(String document) throws InvalidDocumentFormatException;

    /**
     * Generates a cryptographic signature of the data.
     * 
     * @param data data to be signed
     * @return the signed data
     */
    byte[] sign(String data);

    /**
     * Generates a signed document.
     * 
     * @param document the original document
     * @param signature a signature of the document
     * @return a signed document
     */
    String generateSignedDocument(String document, byte[] signature);

}
