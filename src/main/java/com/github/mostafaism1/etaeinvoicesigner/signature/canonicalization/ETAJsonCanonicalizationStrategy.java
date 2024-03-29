package com.github.mostafaism1.etaeinvoicesigner.signature.canonicalization;

import com.github.mostafaism1.etaeinvoicesigner.signature.InvalidDocumentFormatException;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;
import java.io.IOException;

public class ETAJsonCanonicalizationStrategy
  implements CanonicalizationStrategy {

  /**
   * Transforms a valid document to the canonical format specified by the Egyptian Tax Authority
   * (ETA).
   *
   * Refer to <a href=
   * "https://sdk.invoicing.eta.gov.eg/document-serialization-approach/#algorithm-overview">this
   * page</a> for the specification of the canonical format.
   */
  @Override
  public String canonicalize(String document) {
    JsonElement documentAsJson = convertToJson(document);
    return dispatchToCanonicalize(documentAsJson);
  }

  private JsonElement convertToJson(String json) {
    TypeAdapter<JsonElement> strictAdapter = new Gson()
    .getAdapter(JsonElement.class);
    try {
      return strictAdapter.fromJson(json);
    } catch (JsonSyntaxException | IOException e) {
      throw new InvalidDocumentFormatException(e);
    }
  }

  private String dispatchToCanonicalize(JsonElement jsonElement) {
    return dispatchToCanonicalize(jsonElement, "");
  }

  private String dispatchToCanonicalize(JsonElement jsonElement, String key) {
    if (jsonElement.isJsonNull()) {
      return canonicalizeJsonNull(jsonElement.getAsJsonNull());
    } else if (jsonElement.isJsonPrimitive()) {
      return canonicalizeJsonPrimitive(jsonElement.getAsJsonPrimitive());
    } else if (jsonElement.isJsonArray()) {
      return canonicalizeJsonArray(jsonElement.getAsJsonArray(), key);
    } else if (jsonElement.isJsonObject()) {
      return canonicalizeJsonObject(jsonElement.getAsJsonObject());
    } else {
      throw new JsonSyntaxException(
        jsonElement + " is not a valid JsonElement"
      );
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
    StringBuilder result = new StringBuilder();
    for (JsonElement jsonElement : jsonArray) {
      result.append(canonicalizeJsonPropertyName(key));
      result.append(dispatchToCanonicalize(jsonElement));
    }
    return result.toString();
  }

  // Recursive step.
  private String canonicalizeJsonObject(JsonObject jsonObject) {
    StringBuilder result = new StringBuilder();
    for (String key : jsonObject.keySet()) {
      JsonElement jsonElement = jsonObject.get(key);
      String canonicalizedElement = dispatchToCanonicalize(jsonElement, key);
      result.append(canonicalizeJsonPropertyName(key));
      result.append(canonicalizedElement);
    }
    return result.toString();
  }
}
