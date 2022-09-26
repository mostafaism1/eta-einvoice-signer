package com.github.mostafaism1.etaeinvoicesigner.service;

import java.util.Base64;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class ETASignatureMergeStrategy implements SignatureMergeStrategy {

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

}
