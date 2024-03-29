package com.github.mostafaism1.etaeinvoicesigner.signature.canonicalization;

import com.github.mostafaism1.etaeinvoicesigner.signature.InvalidDocumentFormatException;

@FunctionalInterface
public interface CanonicalizationStrategy {
  /**
   * Transforms a document to its canonical format.
   *
   * @param document a valid document
   * @return the document in the canonical format
   * @throws InvalidDocumentFormatException if the document's format is invalid
   */
  String canonicalize(String document);
}
