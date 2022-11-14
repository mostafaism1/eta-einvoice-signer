package com.github.mostafaism1.etaeinvoicesigner.controller;

import com.github.mostafaism1.etaeinvoicesigner.service.DocumentSigningService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/sign")
public class SignatureController {
  private DocumentSigningService documentSigningService;

  @PostMapping
  public String signDocuments(@RequestBody String jsonDocuments) {
    return documentSigningService.generateSignedDocuments(jsonDocuments);
  }
}
