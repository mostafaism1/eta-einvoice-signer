package com.github.mostafaism1.etaeinvoicesigner.signature;

public class InvalidDocumentFormatException extends RuntimeException {

  public InvalidDocumentFormatException() {
    super();
  }

  public InvalidDocumentFormatException(Exception e) {
    super(e);
  }
}
