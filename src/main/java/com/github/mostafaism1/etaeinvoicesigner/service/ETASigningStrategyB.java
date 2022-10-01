// package com.github.mostafaism1.etaeinvoicesigner.service;

// import java.nio.charset.StandardCharsets;
// import java.security.Key;
// import java.security.KeyStore;
// import java.security.MessageDigest;
// import java.security.PrivateKey;
// import java.security.cert.CertStore;
// import java.security.cert.Certificate;
// import java.security.cert.CollectionCertStoreParameters;
// import java.security.cert.X509Certificate;
// import java.util.Base64;
// import java.util.Collections;
// import org.bouncycastle.asn1.ASN1EncodableVector;
// import org.bouncycastle.asn1.ASN1ObjectIdentifier;
// import org.bouncycastle.asn1.DERObjectIdentifier;
// import org.bouncycastle.asn1.DEROctetString;
// import org.bouncycastle.asn1.DERSet;
// import org.bouncycastle.asn1.cms.Attribute;
// import org.bouncycastle.asn1.cms.AttributeTable;
// import org.bouncycastle.asn1.ess.ESSCertIDv2;
// import org.bouncycastle.asn1.ess.SigningCertificateV2;
// import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
// import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
// import org.bouncycastle.cert.X509CertificateHolder;
// import org.bouncycastle.cms.CMSAttributeTableGenerator;
// import org.bouncycastle.cms.CMSProcessable;
// import org.bouncycastle.cms.CMSProcessableByteArray;
// import org.bouncycastle.cms.CMSSignedData;
// import org.bouncycastle.cms.CMSSignedDataGenerator;
// import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
// import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
// import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
// import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.stereotype.Service;


// @Service
// public class ETASigningStrategyB implements SigningStrategy {

// private SecurityFactory securityFactory;
// private char[] tokenPinChars;
// private String certificateAlias;
// private KeyStore keyStore;
// private Certificate certificate;
// private Key privateKey;
// @Value("${pkcs11ConfigFilePath}")
// private String pkcs11ConfigFilePath;
// protected char[] passwordKeystore;
// protected String providerName;

// public ETASigningStrategyB(SecurityFactory securityFactory) {
// this.securityFactory = securityFactory;
// }

// @Override
// public String sign(String data) {
// String tokenPin = "123";
// return getCadesSignature(data, tokenPin);
// }

// private void handleToken(String pin) throws Exception {
// securityFactory.addSecurityProvider();
// this.providerName = securityFactory.getProvider().getName();
// this.passwordKeystore = pin.toCharArray();

// }

// private PrivateKey getPrivateKeyAuth() throws Exception {
// return securityFactory.getPrivateKey();
// }

// private X509Certificate getX509CertificateAuth() throws Exception {
// return securityFactory.getCertificate();
// }


// /**
// *
// * @param pDocumentSer
// * @return
// * @throws Exception
// *
// * Generate Signer Info 1 - Create Attribute Table 2 - Build Signer Info 3 - Generate
// * Signer Info
// */

// private byte[] signDocument(String pDocumentSer) throws Exception {
// MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
// MessageDigest sha256d = MessageDigest.getInstance("SHA-256");

// CMSSignedData cmSignedData;

// ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
// byte[] documentSerHashed = sha256.digest(pDocumentSer.getBytes(StandardCharsets.UTF_8));
// byte[] digestedCert = sha256d.digest(getX509CertificateAuth().getEncoded());

// signedAttributes.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"),
// new DERSet(new DEROctetString(documentSerHashed))));

// AlgorithmIdentifier alCertV2 =
// new AlgorithmIdentifier(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.47"));

// ESSCertIDv2 essCert1 = new ESSCertIDv2(alCertV2, digestedCert);
// ESSCertIDv2[] essCert1Arr = {essCert1};

// SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCert1Arr);

// signedAttributes.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"),
// new DERSet(signingCertificateV2)));

// AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
// signedAttributesTable.toASN1EncodableVector();
// CMSAttributeTableGenerator signedAttributeGenerator =
// new DefaultSignedAttributeTableGenerator(signedAttributesTable);

// SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(
// new JcaDigestCalculatorProviderBuilder().setProvider(providerName).build());

// signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
// signerInfoBuilder.setUnsignedAttributeGenerator(null);

// CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

// JcaContentSignerBuilder contentSigner =
// new JcaContentSignerBuilder("SHA256withRSAEncryption");
// contentSigner.setProvider(providerName);

// signedDataGenerator.addSignerInfoGenerator(
// signerInfoBuilder.build(contentSigner.build(this.getPrivateKeyAuth()),
// new X509CertificateHolder(this.getX509CertificateAuth().getEncoded())));

// CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(
// Collections.singletonList(this.getX509CertificateAuth())));

// signedDataGenerator.addCertificatesAndCRLs(certStore);
// CMSProcessable cmsProcessable =
// new CMSProcessableByteArray(PKCSObjectIdentifiers.digestedData, documentSerHashed);
// CMSSignedData signedData =
// signedDataGenerator.generate(cmsProcessable, false, providerName);

// byte[] DataSignatureForInv = signedData.getEncoded();
// return DataSignatureForInv;
// }

// public String getCadesSignature(String pDocumentSer, String pPin) {
// if (pPin.isEmpty())
// return null;

// byte[] DataSignatureForInv;
// try {
// this.handleToken(pPin);
// DataSignatureForInv = this.signDocument(pDocumentSer);
// return Base64.getEncoder().encodeToString(DataSignatureForInv);
// } catch (Exception e) {
// return "";
// }
// }

// }
