package com.github.mostafaism1.etaeinvoicesigner.service;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class ETASignatureMergeStrategy implements SignatureMergeStrategy {

    @Override
    public String merge(String document, String signature) {
        JsonObject result = new Gson().fromJson(document, JsonObject.class);
        JsonArray signatures = new JsonArray();
        signatures.add(buildIssuerTypeSignature(signature));
        result.add("signatures", signatures);
        return result.toString();
    }

    private JsonObject buildIssuerTypeSignature(String signature) {
        JsonObject result = new JsonObject();
        final String ISSUER_TYPE = "I";
        result.add("signatureType", new JsonPrimitive(ISSUER_TYPE));
        result.add("value", new JsonPrimitive(signature));
        return result;
    }

}
