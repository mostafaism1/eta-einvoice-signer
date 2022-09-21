package com.github.mostafaism1.etaeinvoicesigner.service;

public class InvalidJsonStringException extends RuntimeException {
    public InvalidJsonStringException(String invalidJsonString) {
        super(invalidJsonString + " is not a valid json.");
    }
}
