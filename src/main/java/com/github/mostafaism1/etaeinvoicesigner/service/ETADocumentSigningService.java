package com.github.mostafaism1.etaeinvoicesigner.service;

import org.springframework.stereotype.Service;

@Service
public class ETADocumentSigningService extends AbstractDocumentSigningService {

    @Override
    protected CanonicalizationStrategy createCanonicalizationStrategy() {
        return new ETAJsonCanonicalizationStrategy();
    }

    @Override
    protected SigningStrategy createSigningStrategy() {
        return new ETASigningStrategy();
    }

    @Override
    protected SignatureMergeStrategy createSignatureMergeStrategy() {
        return new ETASignatureMergeStrategy();
    }

}
