package com.github.mostafaism1.etaeinvoicesigner.signature;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
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

  private static class JsonObjectCollector
    implements Collector<JsonObject, JsonArray, JsonArray> {

    public static JsonObjectCollector toJsonObjectCollector() {
      return new JsonObjectCollector();
    }

    @Override
    public Supplier<JsonArray> supplier() {
      return JsonArray::new;
    }

    @Override
    public BiConsumer<JsonArray, JsonObject> accumulator() {
      return (array, object) -> array.add(object);
    }

    @Override
    public BinaryOperator<JsonArray> combiner() {
      return (array1, array2) -> {
        array1.addAll(array2);
        return array1;
      };
    }

    @Override
    public Function<JsonArray, JsonArray> finisher() {
      return jsonArray -> jsonArray;
    }

    @Override
    public Set<Characteristics> characteristics() {
      return Set.of(Characteristics.UNORDERED);
    }
  }
}
