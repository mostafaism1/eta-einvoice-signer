package com.github.mostafaism1.etaeinvoicesigner.signature;

@FunctionalInterface
public interface SignatureMergeStrategy {
  /**
   * Merges a document and its signature into a single signed document.
   *
   * @param document the original document
   * @param signature the document's signature
   * @return the signed document
   */
  String merge(String document, String signature);
}
