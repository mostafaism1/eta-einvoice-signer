package com.github.mostafaism1.etaeinvoicesigner.service;

public interface JsonETACanonicalizationService {
    /**
     * Transforms a valid json string to the canonical format required by the Egyptian Tax Authority (ETA).
     * 
     * Refer to <a href="https://sdk.invoicing.eta.gov.eg/document-serialization-approach/#algorithm-overview">this page</a> for the specification of the canonical format.
     * 
     * @param jsonString a valid json string
     * @return the canonical json string
     * @throws InvalidJsonStringException if jsonString is an invalid json
     */
    String canonicalize(String jsonString) throws InvalidJsonStringException;
}
