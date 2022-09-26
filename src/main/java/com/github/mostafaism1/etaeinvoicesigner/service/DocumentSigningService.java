package com.github.mostafaism1.etaeinvoicesigner.service;

public interface DocumentSigningService {

    /**
     * Transforms a document to its canonical format.
     * 
     * @param document a valid document
     * @return the document in the canonical format
     * @throws InvalidDocumentFormatException if the document's format is invalid
     */
    String canonicalize(String document) throws InvalidDocumentFormatException;

    /**
     * Generates a cryptographic signature of the data.
     * 
     * @param data data to be signed
     * @return the signature
     */
    byte[] sign(String data);

    /**
     * Merges a document and its signature into a single signed document.
     * 
     * @param document the original document
     * @param signature the document's signature
     * @return a signed document
     */
    String generateSignedDocument(String document, byte[] signature);

}
