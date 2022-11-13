package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public enum InMemorySecurityFactory implements SecurityFactory {
  INSTANCE;

  private static final String KEY_ALGORITHM = "RSA";
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSAEncryption";

  private Provider provider;
  private KeyPair keyPair;
  private X509Certificate certificate;

  private InMemorySecurityFactory() {
    provider = new BouncyCastleProvider();
    addSecurityProvider();
    keyPair = generateKeyPair();
    certificate = generateCertificate();
  }

  @Override
  public void addSecurityProvider() {
    Security.addProvider(getProvider());
  }

  @Override
  public PrivateKey getPrivateKey() {
    return keyPair.getPrivate();
  }

  @Override
  public X509Certificate getCertificate() {
    return certificate;
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  private KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(
        KEY_ALGORITHM,
        getProvider()
      );
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private X509Certificate generateCertificate() {
    try {
      X509CertificateHolder certHldr = SecurityUtils.createTrustAnchor(
        keyPair,
        SIGNATURE_ALGORITHM
      );
      certificate = SecurityUtils.convertX509CertificateHolder(certHldr);
      return certificate;
    } catch (
      OperatorCreationException | GeneralSecurityException | IOException e
    ) {
      throw new RuntimeException(e);
    }
  }
}
