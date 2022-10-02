package com.github.mostafaism1.etaeinvoicesigner.service;

import static org.assertj.core.api.BDDAssertions.then;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Testing strategy
 *
 * All the tests in this class are about validating the structure of a generated signature by
 * inspecting the signature's components and comparing them against an expected value.
 */
public class CadesBesSigningStrategyTest {
    private SecurityFactory securityFactory;
    private SigningStrategy signingStrategy;

    private String input;
    private String base64SignedInput;
    private String expected;
    private String actual;
    private byte[] signedInput;


    @BeforeEach
    public void setup() {
        securityFactory = new BouncyCastleSecurityFactory();
        signingStrategy = new CadesBesSigningStrategy(securityFactory);
        input = "input";
        base64SignedInput = signingStrategy.sign(input);
        signedInput = Base64.getDecoder().decode(base64SignedInput);
    }

    @Test
    public void signature_should_be_a_CMS_SignedData_signature() throws IOException, CMSException {
        // Given.

        // When, then.
        assertDoesNotThrow(() -> new CMSSignedData(signedInput));
    }

    @Test
    public void signedData_version_should_be_3() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        int version = signedData.getVersion();

        // Then.
        then(version).isEqualTo(3);
    }

    @Test
    public void signedData_digestAlgorithms_should_be_SHA256() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        Set<AlgorithmIdentifier> digestAlgorithms = signedData.getDigestAlgorithmIDs();

        // Then.
        then(digestAlgorithms).contains(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
    }

    @Test
    public void signedData_encapContentInfo_contentType_should_be_digestData() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        String contentType = signedData.getSignedContentTypeOID();

        // Then.
        then(contentType).isEqualTo(PKCSObjectIdentifiers.digestedData.toString());
    }


    // Can't get at this piece to test it
    @Test
    public void signedData_encapContentInfo_eContent_should_not_be_present() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When, then.
        then(signedData.isDetachedSignature()).isTrue();

    }

    @Test
    public void signedData_certificates_should_contain_only_the_X509_certificate_of_the_signer()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        Store<X509CertificateHolder> certificateStore = signedData.getCertificates();
        Collection<X509CertificateHolder> matches =
                certificateStore.getMatches(new Selector<X509CertificateHolder>() {

                    @Override
                    public boolean match(X509CertificateHolder obj) {
                        try {
                            return obj.equals(new X509CertificateHolder(
                                    securityFactory.getCertificate().getEncoded()));
                        } catch (CertificateEncodingException | IOException e) {
                            e.printStackTrace();
                            return false;
                        }
                    }

                    // This is a dummy implementation since the method is never called by the test.
                    @Override
                    public Object clone() {
                        return null;
                    }
                });

        // Then.
        then(matches.size()).isEqualTo(1);
    }

    @Test
    public void signedData_signerInfos_should_contain_only_one_signerInfo_in_the_signature()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformationStore signerInfos = signedData.getSignerInfos();

        // Then.
        then(signerInfos.size()).isEqualTo(1);
    }

    @Test
    public void signerInfo_version_should_be_1() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getVersion()).isEqualTo(1);
    }

    @Test
    public void signerInfo_sId_should_be_issuerAndSerialNumber_and_should_contain_the_serial_number_of_the_certificate_and_issuer_name()
            throws CMSException, CertificateParsingException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSID().getIssuer().toString())
                .isEqualTo(securityFactory.getCertificate().getIssuerX500Principal().getName());
        then(signerInfo.getSID().getSerialNumber())
                .isEqualTo(securityFactory.getCertificate().getSerialNumber());
    }

    @Test
    public void signerInfo_digestAlgorithms_should_be_SHA256() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getDigestAlgOID()).isEqualTo(NISTObjectIdentifiers.id_sha256.toString());
    }

    @Test
    public void signerInfo_signedAttrs_should_contain_at_least_4_attributes() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes().size()).isGreaterThanOrEqualTo(4);
    }

    @Test
    public void signerInfo_signedAttrs_should_contain_a_contentType_attribute()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.3")))
                .isNotNull();
    }

    @Test
    public void signerInfo_signedAttrs_should_contain_the_a_messageDigest_attribute()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4")))
                .isNotNull();
    }

    @Test
    public void signerInfo_signedAttrs_should_contain_a_signingTime_attribute()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5")))
                .isNotNull();
    }

    @Test
    public void signerInfo_signedAttrs_should_contain_an_ESSSigningCertificatV2_attribute()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes()
                .get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"))).isNotNull();
    }

    @Test
    public void signerInfo_signedAttrs_ContentType_should_be_DigestData() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.3"))
                .getAttrValues().getObjectAt(0)).isEqualTo(PKCSObjectIdentifiers.digestedData);
    }

    @Test
    public void signerInfo_signedAttrs_MessageDigest_should_contain_Der_Octet_String_format_for_SHA256_Hash_of_the_data_to_be_signed()
            throws CMSException, NoSuchAlgorithmException, OperatorCreationException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);
        MessageDigest sha256d = MessageDigest.getInstance("SHA-256");

        // When.
        ASN1Encodable messageDigest = signedData.getSignerInfos().getSigners().iterator().next()
                .getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"))
                .getAttrValues().getObjectAt(0);

        // then
        then(messageDigest).isEqualTo(new DEROctetString(sha256d.digest(input.getBytes())));

    }

    @Test
    public void signerInfo_signedAttrs_ESSSigningCertificateV2_should_contains_SHA256_hash_of_the_signer_certificate()
            throws CMSException, NoSuchAlgorithmException, CertificateEncodingException,
            IOException {

        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);
        MessageDigest sha256d = MessageDigest.getInstance("SHA-256");

        // When.
        var certificateDigest = signedData.getSignerInfos().getSigners().iterator().next()
                .getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47"))
                .getAttrValues().getObjectAt(0);

        ESSCertIDv2[] certsIDv2 = SigningCertificateV2.getInstance(certificateDigest).getCerts();
        ESSCertIDv2 certIDv2 = certsIDv2[0];
        byte[] certIDv2Hash = certIDv2.getCertHash();

        // Then.
        byte[] expected = sha256d.digest(securityFactory.getCertificate().getEncoded());
        then(certIDv2Hash).isEqualTo(expected);
    }

    @Test
    public void signerInfo_signedAttrs_SigningTime_should_be_the_machine_time_in_UTC()
            throws CMSException, ParseException, InterruptedException {

        // Given.
        Date before = new Date();
        final int UTCTIME_LOWEST_TIME_RESOLUTION_IN_SECONDS = 1;
        TimeUnit.SECONDS.sleep(UTCTIME_LOWEST_TIME_RESOLUTION_IN_SECONDS);
        base64SignedInput = signingStrategy.sign(input);
        signedInput = Base64.getDecoder().decode(base64SignedInput);
        CMSSignedData signedData = new CMSSignedData(signedInput);
        TimeUnit.SECONDS.sleep(UTCTIME_LOWEST_TIME_RESOLUTION_IN_SECONDS);
        Date after = new Date();

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();
        ASN1Encodable signingTime = signerInfo.getSignedAttributes()
                .get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5")).getAttrValues()
                .getObjectAt(0);

        ASN1UTCTime ASN1UTCTime = org.bouncycastle.asn1.ASN1UTCTime.getInstance(signingTime);
        Date date = ASN1UTCTime.getDate();
        // Then.
        then(before.before(date)).isTrue();
        then(after.after(date)).isTrue();

    }

    @Test
    public void signerInfo_signatureAlgorithm_SignatureAlgorithmIdentifier_should_be_sha256WithRSAEncryption()
            throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getEncryptionAlgOID())
                .isEqualTo(PKCSObjectIdentifiers.sha256WithRSAEncryption.toString());
    }

    @Test
    public void signerInfo_Signature_should_be_Signature_value_computed_on_the_user_data_and_on_the_signed_attributes_using_the_signer_private_key_with_Algorithm_sha256WithRSAEncryption()
            throws CMSException, NoSuchAlgorithmException, IOException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeySpecException, CertificateException, OperatorCreationException,
            SignatureException {


        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        byte[] signature =
                signedData.getSignerInfos().getSigners().iterator().next().getSignature();

        // When.
        byte[] encodedSignedAttributes = signedData.getSignerInfos().getSigners().iterator().next()
                .getEncodedSignedAttributes();

        Signature verifier =
                Signature.getInstance("SHA256withRSAEncryption", securityFactory.getProvider());
        verifier.initVerify(securityFactory.getCertificate().getPublicKey());
        verifier.update(encodedSignedAttributes);
        boolean actual = verifier.verify(signature);

        // Then.
        then(actual).isTrue();
    }


    @Test
    public void signerInfo_unsignedAttrs_should_not_be_present() throws CMSException {
        // Given.
        CMSSignedData signedData = new CMSSignedData(signedInput);

        // When.
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();

        // Then.
        then(signerInfo.getUnsignedAttributes()).isNull();
    }

}
