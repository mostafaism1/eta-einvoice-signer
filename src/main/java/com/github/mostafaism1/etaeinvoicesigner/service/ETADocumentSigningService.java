package com.github.mostafaism1.etaeinvoicesigner.service;

import org.springframework.stereotype.Service;

@Service
public class ETADocumentSigningService extends AbstractDocumentSigningService {

    public ETADocumentSigningService(DocumentSigningFactory documentSigningFactory) {
        super(new ETADocumentSigningFactory());
    }

}
