package com.github.mostafaism1.etaeinvoicesigner.service;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

class JsonObjectCollector
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
