package com.github.mostafaism1.etaeinvoicesigner.service;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface SecurityFactory {

    void addSecurityProvider();

    PrivateKey getPrivateKey();

    X509Certificate getCertificate();

}
