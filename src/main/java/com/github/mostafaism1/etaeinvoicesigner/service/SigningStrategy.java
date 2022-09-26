package com.github.mostafaism1.etaeinvoicesigner.service;

public interface SigningStrategy {

    /**
     * Generates a cryptographic signature of the data.
     * 
     * @param data data to be signed
     * @return the signature
     */
    byte[] sign(String data);

}
