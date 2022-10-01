package com.github.mostafaism1.etaeinvoicesigner.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
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
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class CadesBesSigningStrategy implements SigningStrategy {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSAEncryption";
    private SecurityFactory securityFactory;

    public CadesBesSigningStrategy(SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }


    @Override
    public String sign(String data) {
        try {
            X509CertificateHolder signingCert =
                    new X509CertificateHolder(securityFactory.getCertificate().getEncoded());
            CMSSignedData signedData = createSignedData(securityFactory.getPrivateKey(),
                    signingCert, data.getBytes(), false);
            return Base64.getEncoder().encodeToString(signedData.getEncoded());
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }


    public CMSSignedData createSignedData(PrivateKey signingKey, X509CertificateHolder signingCert,
            byte[] msg, boolean encapsulate) throws CMSException, OperatorCreationException {

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(securityFactory.getProvider()).build(signingKey);

        DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider()).build();

        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestCalcProvider)
                .setSignedAttributeGenerator(new CMSAttributeTableGenerator() {
                    public AttributeTable getAttributes(Map parameters)
                            throws CMSAttributeTableGenerationException {
                        AttributeTable table = new DefaultSignedAttributeTableGenerator()
                                .getAttributes(parameters);


                        // TODO hash the msg first

                        table.remove(CMSAttributes.messageDigest);
                        MessageDigest md;
                        try {
                            md = MessageDigest.getInstance("SHA-256");
                        } catch (NoSuchAlgorithmException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                            return null;
                        }
                        table.add(CMSAttributes.messageDigest,
                                new DERSet(new DEROctetString(md.digest(msg))));

                        // table.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"),
                        // new DERSet(signingCertificateV2));

                        table.remove(CMSAttributes.signingTime);
                        table.add(CMSAttributes.signingTime,
                                new DERSet(new ASN1UTCTime(new Date())));

                        table.remove(CMSAttributes.cmsAlgorithmProtect);

                        table.remove(CMSAttributes.contentType);
                        return table.add(CMSAttributes.contentType,
                                PKCSObjectIdentifiers.digestedData);

                    }
                }).build(contentSigner, signingCert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfoGenerator);

        Store<X509CertificateHolder> certs =
                new CollectionStore<X509CertificateHolder>(Collections.singletonList(signingCert));

        gen.addCertificates(certs);

        CMSTypedData typedMsg = new CMSProcessableByteArray(msg);

        return gen.generate(typedMsg, encapsulate);
    }
}
