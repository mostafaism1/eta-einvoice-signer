package com.github.mostafaism1.etaeinvoicesigner.service;

public interface DocumentSigningService {
  /**
   * Generates a collection of signed documents.
   *
   * @param documents a collection of documents
   * @return the collection of signed documents
   * @throws InvalidDocumentFormatException if the documents' format is invalid
   */
  String generateSignedDocuments(String documents);

  /**
   * Generates a signed document.
   *
   * @param document a document
   * @return the signed document
   * @throws InvalidDocumentFormatException if the document's format is invalid
   */
  String generateSignedDocument(String document);
}
