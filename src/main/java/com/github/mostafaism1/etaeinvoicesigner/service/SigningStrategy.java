package com.github.mostafaism1.etaeinvoicesigner.service;

@FunctionalInterface
public interface SigningStrategy {
  /**
   * Generates a cryptographic signature of the data.
   *
   * @param data data to be signed
   * @return the signature
   */
  String sign(String data);
}
