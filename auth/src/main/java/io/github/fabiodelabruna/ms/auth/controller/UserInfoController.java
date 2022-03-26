package io.github.fabiodelabruna.ms.auth.controller;

import io.github.fabiodelabruna.ms.core.model.ApplicationUser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/user")
public class UserInfoController {

    @GetMapping(path = "/info", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<ApplicationUser> getUserInfo(final Principal principal) {
        final ApplicationUser user = (ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

}
