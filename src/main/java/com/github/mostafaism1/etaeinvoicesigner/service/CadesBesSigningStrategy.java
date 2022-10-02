package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CadesBesSigningStrategy implements SigningStrategy {

        private static final String SIGNATURE_ALGORITHM = "SHA256withRSAEncryption";
        private SecurityFactory securityFactory;

        public CadesBesSigningStrategy(SecurityFactory securityFactory) {
                this.securityFactory = securityFactory;
        }


        @Override
        public String sign(String data) {
                try {
                        X509CertificateHolder signingCert = new X509CertificateHolder(
                                        securityFactory.getCertificate().getEncoded());
                        CMSSignedData signedData = createSignedData(securityFactory.getPrivateKey(),
                                        signingCert, data.getBytes(), false);
                        return Base64.getEncoder().encodeToString(signedData.getEncoded());
                } catch (Exception e) {
                        System.out.println(e);
                        return null;
                }
        }


        public CMSSignedData createSignedData(PrivateKey signingKey,
                        X509CertificateHolder signingCert, byte[] msg, boolean encapsulate)
                        throws CMSException, OperatorCreationException, NoSuchAlgorithmException,
                        IOException {
                ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                signedAttributes.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"),
                                new DERSet(new DEROctetString(sha256.digest(msg)))));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                                new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"));
                ESSCertIDv2 essCert1 = new ESSCertIDv2(algorithmIdentifier,
                                sha256.digest(signingCert.getEncoded()));

                ESSCertIDv2[] essCert1Arr = {essCert1};

                SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCert1Arr);

                signedAttributes.add(new Attribute(
                                new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"),
                                new DERSet(signingCertificateV2)));

                AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
                signedAttributesTable.toASN1EncodableVector();
                CMSAttributeTableGenerator signedAttributeGenerator =
                                new DefaultSignedAttributeTableGenerator(signedAttributesTable);

                SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder()
                                                .setProvider(securityFactory.getProvider())
                                                .build());

                signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);

                signerInfoBuilder.setUnsignedAttributeGenerator(null);


                JcaContentSignerBuilder contentSigner =
                                new JcaContentSignerBuilder("SHA256withRSAEncryption");
                contentSigner.setProvider(securityFactory.getProvider());

                CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

                signedDataGenerator.addSignerInfoGenerator(signerInfoBuilder.build(
                                contentSigner.build(signingKey),
                                new X509CertificateHolder(signingCert.getEncoded())));

                // CertStore certStore = CertStore.getInstance("Collection",
                // new CollectionCertStoreParameters(
                // Collections.singletonList(signingCert)));

                signedDataGenerator.addCertificate(signingCert);
                // CMSProcessable cmsProcessable = new CMSProcessableByteArray(
                // PKCSObjectIdentifiers.digestedData, sha256.digest(msg));
                CMSTypedData cmsTypedData = new CMSProcessableByteArray(
                                PKCSObjectIdentifiers.digestedData, msg);
                CMSSignedData signedData = signedDataGenerator.generate(cmsTypedData, false);

                return signedData;
        }


}
