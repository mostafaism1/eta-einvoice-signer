package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class ETASigningStrategyB implements SigningStrategy {

    private char[] tokenPinChars;
    private String providerName;
    private String certificateAlias;
    private KeyStore keyStore;
    private Certificate certificate;
    private Key privateKey;
    private String pkcs11ConfigFilePath = "";

    @Override
    public String sign(String data) {
        String tokenPin = "";
        return generateCadesSignature(data, tokenPin);
    }

    public String generateCadesSignature(String canonicalDocument, String tokenPin) {
        if (tokenPin.isEmpty())
            return null;

        byte[] signature;
        try {
            loadPKCS11Implementation(tokenPin);
            signature = this.signDocument(canonicalDocument);
            return encodeSignature(signature);
        } catch (Exception e) {
            return "";
        }
    }

    private void loadPKCS11Implementation(String pin) throws Exception {

        String providerName = "SunPKCS11";
        Provider provider = Security.getProvider(providerName);
        provider = provider.configure(pkcs11ConfigFilePath);
        Security.addProvider(provider);
        this.providerName = providerName;
        this.tokenPinChars = pin.toCharArray();

        keyStore = KeyStore.getInstance("PKCS11");
        keyStore.load(null, this.tokenPinChars);

        Enumeration<String> aliases = keyStore.aliases();
        if (aliases.hasMoreElements()) {
            certificateAlias = aliases.nextElement();
        }

        certificate = (Certificate) keyStore.getCertificate(certificateAlias);
        privateKey = keyStore.getKey(certificateAlias, this.tokenPinChars);
    }

    private byte[] signDocument(String canonicalDocument) throws Exception {
        byte[] documentDigest = hash(canonicalDocument.getBytes(StandardCharsets.UTF_8));
        byte[] certificateDigest = hash(getX509CertificateAuth().getEncoded());
        CMSSignedDataGenerator signedDataGenerator =
                buildSignedData(documentDigest, certificateDigest);
        CMSProcessable content =
                new CMSProcessableByteArray(PKCSObjectIdentifiers.digestedData, documentDigest);
        CMSSignedData signedData = signedDataGenerator.generate(content, false, providerName);
        return signedData.getEncoded();
    }

    private byte[] hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(data);
    }

    private CMSSignedDataGenerator buildSignedData(byte[] documentDigest, byte[] certificateDigest)
            throws CertificateEncodingException, IOException, Exception {

        CMSSignedDataGenerator result = new CMSSignedDataGenerator();
        SignerInfoGeneratorBuilder signerInfoBuilder =
                buildSignerInfo(documentDigest, certificateDigest);
        JcaContentSignerBuilder contentSigner =
                new JcaContentSignerBuilder("SHA256withRSAEncryption");
        contentSigner.setProvider(providerName);
        result.addSignerInfoGenerator(
                signerInfoBuilder.build(contentSigner.build(this.getPrivateKeyAuth()),
                        new X509CertificateHolder(this.getX509CertificateAuth().getEncoded())));
        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(
                Collections.singletonList(this.getX509CertificateAuth())));
        result.addCertificatesAndCRLs(certStore);
        return result;

    }

    private SignerInfoGeneratorBuilder buildSignerInfo(byte[] documentDigest,
            byte[] certificateDigest) throws OperatorCreationException {
        CMSAttributeTableGenerator signedAttributeGenerator =
                buildAttributeTable(documentDigest, certificateDigest);
        SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(providerName).build());
        signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
        signerInfoBuilder.setUnsignedAttributeGenerator(null);
        return signerInfoBuilder;
    }

    private CMSAttributeTableGenerator buildAttributeTable(byte[] messageDigest,
            byte[] certificateDigest) {
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        addMessageDigestAttribute(messageDigest, signedAttributes);
        addESSSigningCertificateV2Attribute(certificateDigest, signedAttributes);
        AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
        signedAttributesTable.toASN1EncodableVector();
        return new DefaultSignedAttributeTableGenerator(signedAttributesTable);
    }

    private void addMessageDigestAttribute(byte[] documentDigest,
            ASN1EncodableVector signedAttributes) {
        signedAttributes.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"),
                new DERSet(new DEROctetString(documentDigest))));
    }

    private void addESSSigningCertificateV2Attribute(byte[] certificateDigest,
            ASN1EncodableVector signedAttributes) {
        SigningCertificateV2 signingCertificateV2 =
                generateESSSigningCertificateV2(certificateDigest);
        signedAttributes.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"),
                new DERSet(signingCertificateV2)));
    }

    private SigningCertificateV2 generateESSSigningCertificateV2(byte[] certificateDigest) {
        AlgorithmIdentifier alCertV2 =
                new AlgorithmIdentifier(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.47"));
        ESSCertIDv2 essCert1 = new ESSCertIDv2(alCertV2, certificateDigest);
        ESSCertIDv2[] essCert1Arr = {essCert1};
        SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCert1Arr);
        return signingCertificateV2;
    }

    private String encodeSignature(byte[] signature) {
        return Base64.getEncoder().encodeToString(signature);
    }

    private PrivateKey getPrivateKeyAuth() throws Exception {
        if (privateKey instanceof PrivateKey) {
            return (PrivateKey) privateKey;
        }
        return null;
    }

    private X509Certificate getX509CertificateAuth() throws Exception {
        if (certificate instanceof X509Certificate) {
            return (X509Certificate) certificate;
        }
        return null;
    }

}
