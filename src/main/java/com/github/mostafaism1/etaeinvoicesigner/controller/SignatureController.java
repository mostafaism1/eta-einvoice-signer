package com.github.mostafaism1.etaeinvoicesigner.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import com.github.mostafaism1.etaeinvoicesigner.service.DocumentSigningService;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Controller("/")
public class SignatureController {

    private DocumentSigningService documentSigningService;

    @PostMapping("")
    @ResponseBody
    public String sign(@RequestBody String jsonDocument) {
        return documentSigningService.generateSignedDocument(jsonDocument);
    }
}
