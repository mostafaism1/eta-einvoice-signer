package com.github.mostafaism1.etaeinvoicesigner.service;

public class InvalidDocumentFormatException extends RuntimeException {

  public InvalidDocumentFormatException(String invalidDocument) {
    super(invalidDocument + " is not a valid document.");
  }
}
