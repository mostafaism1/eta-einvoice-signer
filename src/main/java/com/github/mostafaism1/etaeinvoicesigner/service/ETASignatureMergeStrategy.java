package com.github.mostafaism1.etaeinvoicesigner.service;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class ETASignatureMergeStrategy implements SignatureMergeStrategy {

    @Override
    public String merge(String document, String signature) {
        JsonArray signatures = new JsonArray();
        JsonObject signatureObject = new JsonObject();
        signatureObject.add("signatureType", new JsonPrimitive("I"));
        signatureObject.add("value", new JsonPrimitive(signature));
        signatures.add(signatureObject);
        Gson gson = new Gson();
        JsonObject signedDocument = gson.fromJson(document, JsonObject.class);
        signedDocument.add("signatures", signatures);
        return signedDocument.toString();
    }

}
