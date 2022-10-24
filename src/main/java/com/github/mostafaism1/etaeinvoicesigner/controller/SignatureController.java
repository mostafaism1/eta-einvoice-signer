package com.github.mostafaism1.etaeinvoicesigner.controller;

import com.github.mostafaism1.etaeinvoicesigner.service.DocumentSigningService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@AllArgsConstructor
@Controller("/")
public class SignatureController {
  private DocumentSigningService documentSigningService;

  @PostMapping("")
  @ResponseBody
  public String signDocument(@RequestBody String jsonDocument) {
    return documentSigningService.generateSignedDocument(jsonDocument);
  }

  @PostMapping("bulk")
  @ResponseBody
  public String signDocuments(@RequestBody String jsonDocuments) {
    return documentSigningService.generateSignedDocuments(jsonDocuments);
  }
}
