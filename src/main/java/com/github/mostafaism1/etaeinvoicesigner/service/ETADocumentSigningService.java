package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
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
            return signWithPrivateKey(dataInBytes, privateKey);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException
                | CertificateException | IOException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
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
