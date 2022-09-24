package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Service
public class ETADocumentSigningService implements DocumentSigningService {

    @Value("${pkcs11ConfigFilePath}")
    private String pkcs11ConfigFilePath;
    @Value("${keyStorePassword}")
    private String keyStorePassword;
    @Value("${certificateAlias}")
    private String certificateAlias;

    /**
     * Transforms a valid document to the canonical format specified by the Egyptian Tax Authority
     * (ETA).
     * 
     * Refer to <a href=
     * "https://sdk.invoicing.eta.gov.eg/document-serialization-approach/#algorithm-overview">this
     * page</a> for the specification of the canonical format.
     */
    @Override
    public String canonicalize(String document) throws InvalidDocumentFormatException {
        if (!isValid(document)) {
            throw new InvalidDocumentFormatException(document);
        }
        Gson gson = new Gson();
        JsonElement jsonElement = gson.fromJson(document, JsonElement.class);
        return dispatchToCanonicalize(jsonElement);
    }

    /**
     * Creates a CADES-BES signature.
     * 
     * Refer to <a href=
     * "https://sdk.invoicing.eta.gov.eg/document-serialization-approach/#algorithm-overview">this
     * document</a> for the specifications of a CADES-BES signature.
     */
    @Override
    public byte[] sign(String data) {
        byte[] dataInBytes = data.getBytes(StandardCharsets.UTF_8);
        loadPKCS11Implementation();
        try {
            PrivateKey privateKey = getPrivateKey();
            X509Certificate x509Certificate = getCertificate();

            // Prepare signing certificate
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] certificateDigest = sha256.digest(x509Certificate.getEncoded());

            AlgorithmIdentifier algoIdSha256 =
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

            ESSCertIDv2 essCert1 = new ESSCertIDv2(algoIdSha256, certificateDigest);
            SigningCertificateV2 signingCertificate =
                    new SigningCertificateV2(new ESSCertIDv2[] {essCert1});

            // Prepare signed message digest provider
            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

            // Prepare message signer
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);

            // Prepare signature additional info generator
            JcaSignerInfoGeneratorBuilder builder =
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);
            builder.setSignedAttributeGenerator(attributes -> {
                CMSAttributeTableGenerator tableGenerator =
                        new DefaultSignedAttributeTableGenerator();
                // At this moment Content-Type and Message-Digest attributes are already
                // present. So, to be compliant with CAdES-BES we have to add
                // Signing-Certificate attribute.
                return tableGenerator.getAttributes(attributes)
                        .add(PKCSObjectIdentifiers.id_aa_signingCertificateV2, signingCertificate);
            });
            SignerInfoGenerator signerInfoGenerator = builder.build(contentSigner, x509Certificate);

            // Prepare CMS signed data generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(signerInfoGenerator);
            generator.addCertificates(new JcaCertStore(Collections.singleton(x509Certificate)));

            // Sign
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(dataInBytes);
            CMSSignedData cmsSignedData = generator.generate(cmsTypedData);

            return cmsSignedData.getEncoded();
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException | CMSException | OperatorCreationException e) {
            e.printStackTrace();
        }
        return null;
    }

    private X509Certificate getCertificate()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        String keyStoreType = "PKCS11";
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, keyStorePassword.toCharArray());
        X509Certificate x509Certificate =
                (X509Certificate) keyStore.getCertificate(certificateAlias);
        return x509Certificate;
    }

    @Override
    public String generateSignedDocument(String document, byte[] signature) {
        JsonArray signatures = new JsonArray();
        JsonObject signatureObject = new JsonObject();
        signatureObject.add("signatureType", new JsonPrimitive("I"));
        signatureObject.add("value",
                new JsonPrimitive(Base64.getEncoder().encodeToString(signature)));
        signatures.add(signatureObject);
        Gson gson = new Gson();
        JsonObject signedDocument = gson.fromJson(document, JsonObject.class);
        signedDocument.add("signatures", signatures);
        return signedDocument.toString();

    }


    private boolean isValid(String json) {
        TypeAdapter<JsonElement> strictAdapter = new Gson().getAdapter(JsonElement.class);
        try {
            strictAdapter.fromJson(json);
        } catch (JsonSyntaxException | IOException e) {
            return false;
        }
        return true;
    }

    private String dispatchToCanonicalize(JsonElement jsonElement) {
        return dispatchToCanonicalize(jsonElement, "");
    }

    private String dispatchToCanonicalize(JsonElement jsonElement, String key) {
        if (jsonElement.isJsonNull()) {
            return canonicalizeJsonNull((JsonNull) jsonElement);
        } else if (jsonElement.isJsonPrimitive()) {
            return canonicalizeJsonPrimitive((JsonPrimitive) jsonElement);
        } else if (jsonElement.isJsonArray()) {
            return canonicalizeJsonArray((JsonArray) jsonElement, key);
        } else if (jsonElement.isJsonObject()) {
            return canonicalizeJsonObject((JsonObject) jsonElement);
        } else {
            throw new JsonSyntaxException(jsonElement + " is not a valid JsonElement");
        }
    }

    // Base case.
    private String canonicalizeJsonPropertyName(String propertyName) {
        return "\"" + propertyName.toUpperCase() + "\"";
    }

    // Base case.
    private String canonicalizeJsonNull(JsonNull jsonNull) {
        return "";
    }

    // Base case.
    private String canonicalizeJsonPrimitive(JsonPrimitive jsonPrimitive) {
        return "\"" + jsonPrimitive.getAsString() + "\"";
    }

    // Recursive step.
    private String canonicalizeJsonArray(JsonArray jsonArray, String key) {
        StringBuilder sb = new StringBuilder();
        for (JsonElement jsonElement : jsonArray) {
            sb.append(canonicalizeJsonPropertyName(key));
            sb.append(dispatchToCanonicalize(jsonElement));
        }
        return sb.toString();
    }

    // Recursive step.
    private String canonicalizeJsonObject(JsonObject jsonObject) {
        StringBuilder sb = new StringBuilder();
        for (String key : jsonObject.keySet()) {
            JsonElement jsonElement = jsonObject.get(key);
            String canonicalizedElement = dispatchToCanonicalize(jsonElement, key);
            sb.append(canonicalizeJsonPropertyName(key));
            sb.append(canonicalizedElement);
        }
        return sb.toString();
    }

    private void loadPKCS11Implementation() {
        String providerName = "SunPKCS11";
        Provider provider = Security.getProvider(providerName);
        provider = provider.configure(pkcs11ConfigFilePath);
        Security.addProvider(provider);
    }

    private PrivateKey getPrivateKey() throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        String keyStoreType = "PKCS11";
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, keyStorePassword.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateAlias, null);
        return privateKey;
    }

    private byte[] signWithPrivateKey(byte[] data, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String signatureAlgorithm = "SHA256withRSA";
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }


}
