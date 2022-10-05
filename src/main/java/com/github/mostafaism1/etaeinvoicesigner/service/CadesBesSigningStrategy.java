package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class CadesBesSigningStrategy implements SigningStrategy {

        private static final Provider DIGEST_PROVIDER = new BouncyCastleProvider();
        private static final String DIGEST_ALGORITHM = "SHA-256";
        private static final String SIGNATURE_ALGORITHM = "SHA256withRSAEncryption";

        private Provider signatureProvider;
        private PrivateKey signingKey;
        private Certificate signingCert;

        public CadesBesSigningStrategy(SecurityFactory securityFactory) {
                this.signatureProvider = securityFactory.getProvider();
                this.signingKey = securityFactory.getPrivateKey();
                this.signingCert = securityFactory.getCertificate();
        }

        @Override
        public String sign(String data) {
                CMSSignedData signedData;
                try {
                        signedData = buildCMSSignedData(data.getBytes(), false);
                        return Base64.getEncoder().encodeToString(signedData.getEncoded());
                } catch (CertificateEncodingException | OperatorCreationException
                                | NoSuchAlgorithmException | CMSException | IOException e) {
                        e.printStackTrace();
                        return null;
                }
        }


        public CMSSignedData buildCMSSignedData(byte[] msg, boolean encapsulate)
                        throws CertificateEncodingException, NoSuchAlgorithmException,
                        OperatorCreationException, IOException, CMSException {

                CMSSignedDataGenerator signedDataGenerator = buildCMSSignedDataGenerator(msg);
                CMSTypedData cmsTypedData = new CMSProcessableByteArray(
                                PKCSObjectIdentifiers.digestedData, msg);
                return signedDataGenerator.generate(cmsTypedData, false);
        }

        private CMSSignedDataGenerator buildCMSSignedDataGenerator(byte[] msg)
                        throws CertificateEncodingException, OperatorCreationException,
                        NoSuchAlgorithmException, IOException, CMSException {

                SignerInfoGenerator signerInfoGenerator = buildSignerInfoGenerator(msg);
                CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
                signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
                signedDataGenerator.addCertificate(
                                new X509CertificateHolder(signingCert.getEncoded()));
                return signedDataGenerator;
        }

        private SignerInfoGenerator buildSignerInfoGenerator(byte[] msg)
                        throws CertificateEncodingException, NoSuchAlgorithmException,
                        OperatorCreationException, IOException {

                AttributeTable signedAttributesTable = buildSignedAttributeTable(msg);

                CMSAttributeTableGenerator signedAttributeGenerator =
                                new DefaultSignedAttributeTableGenerator(signedAttributesTable);

                ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                                .setProvider(signatureProvider).build(signingKey);

                DigestCalculatorProvider digestCalcProvider =
                                new JcaDigestCalculatorProviderBuilder()
                                                .setProvider(DIGEST_PROVIDER).build();
                SignerInfoGenerator signerInfoGenerator =
                                new SignerInfoGeneratorBuilder(digestCalcProvider)
                                                .setSignedAttributeGenerator(
                                                                signedAttributeGenerator)
                                                .setUnsignedAttributeGenerator(null)
                                                .build(contentSigner, new X509CertificateHolder(
                                                                signingCert.getEncoded()));
                return signerInfoGenerator;
        }

        private AttributeTable buildSignedAttributeTable(byte[] msg)
                        throws NoSuchAlgorithmException, CertificateEncodingException {

                ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
                signedAttributes.add(buildSigningCertificateV2Attribute());
                return new AttributeTable(signedAttributes);
        }

        private Attribute buildSigningCertificateV2Attribute()
                        throws CertificateEncodingException, NoSuchAlgorithmException {

                MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
                ASN1ObjectIdentifier attributeIdentifier = ASN1ObjectIdentifier
                                .getInstance(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                AlgorithmIdentifier algorithmIdentifier =
                                new AlgorithmIdentifier(attributeIdentifier);
                ESSCertIDv2 essCert = new ESSCertIDv2(algorithmIdentifier,
                                digester.digest(signingCert.getEncoded()));
                ESSCertIDv2[] essCerts = {essCert};
                SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCerts);
                DERSet attributeValue = new DERSet(signingCertificateV2);
                return new Attribute(attributeIdentifier, attributeValue);
        }

}