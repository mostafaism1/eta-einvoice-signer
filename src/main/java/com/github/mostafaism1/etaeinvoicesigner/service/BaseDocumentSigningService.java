package com.github.mostafaism1.etaeinvoicesigner.service;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.stream.StreamSupport;

public abstract class BaseDocumentSigningService
  implements DocumentSigningService {
  private final String DOCUMENTS_ARRAY_KEY = "documents";
  private DocumentSigningFactory documentSigningFactory;
  private Gson gson;

  protected BaseDocumentSigningService() {
    documentSigningFactory = getDocumentSigningFactory();
    gson = new Gson();
  }

  @Override
  public String generateSignedDocuments(String documents) {
    JsonArray unsignedDocuments = extractUnsignedDocuments(documents);
    JsonArray signedDocuments = signDocuments(unsignedDocuments);
    JsonObject result = wrapSignedDocuments(signedDocuments);
    return result.toString();
  }

  @Override
  public String generateSignedDocument(String document) {
    String canonicalizedDocument = documentSigningFactory
      .getCanonicalizationStrategy()
      .canonicalize(document);
    String signature = documentSigningFactory
      .getSigningStrategy()
      .sign(canonicalizedDocument);
    return documentSigningFactory
      .getSignatureMergeStrategy()
      .merge(document, signature);
  }

  protected abstract DocumentSigningFactory getDocumentSigningFactory();

  private JsonArray extractUnsignedDocuments(String documents) {
    JsonArray unsignedDocuments = gson
      .fromJson(documents, JsonObject.class)
      .get(DOCUMENTS_ARRAY_KEY)
      .getAsJsonArray();
    return unsignedDocuments;
  }

  private JsonObject wrapSignedDocuments(JsonArray signedDocuments) {
    JsonObject result = new JsonObject();
    result.add(DOCUMENTS_ARRAY_KEY, signedDocuments);
    return result;
  }

  private JsonArray signDocuments(JsonArray unsignedDocuments) {
    return StreamSupport
      .stream(unsignedDocuments.spliterator(), true)
      .map(
        unsignedDocument -> generateSignedDocument(unsignedDocument.toString())
      )
      .map(signedDocument -> gson.fromJson(signedDocument, JsonObject.class))
      .collect(JsonObjectCollector.toJsonObjectCollector());
  }
}
