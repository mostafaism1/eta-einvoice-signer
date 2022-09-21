package com.github.mostafaism1.etaeinvoicesigner.service;

import java.io.IOException;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;

public class DefaultJsonETACanonicalizationService implements JsonETACanonicalizationService {

    @Override
    public String canonicalize(String jsonString) {
        if (!isValid(jsonString)) {
            throw new InvalidJsonStringException(jsonString);
        }
        Gson gson = new Gson();
        JsonElement jsonElement = gson.fromJson(jsonString, JsonElement.class);
        return dispatchToCanonicalize(jsonElement);
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
            throw new IllegalArgumentException(jsonElement + " is not a valid JsonElement");
        }
    }

    // Base case.
    private String canonicalizePropertyName(String str) {
        return "\"" + str.toUpperCase() + "\"";
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
    private String canonicalizeJsonObject(JsonObject jsonObject) {
        StringBuilder sb = new StringBuilder();
        for (String key : jsonObject.keySet()) {
            JsonElement jsonElement = jsonObject.get(key);
            String canonicalizedElement = dispatchToCanonicalize(jsonElement, key);
            sb.append(canonicalizePropertyName(key));
            sb.append(canonicalizedElement);
        }
        return sb.toString();
    }

    // Recursive step.
    private String canonicalizeJsonArray(JsonArray jsonArray, String key) {
        StringBuilder sb = new StringBuilder();
        for (JsonElement jsonElement : jsonArray) {
            sb.append(canonicalizePropertyName(key));
            sb.append(dispatchToCanonicalize(jsonElement));
        }
        return sb.toString();
    }

}
