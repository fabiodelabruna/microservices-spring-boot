package io.github.fabiodelabruna.ms.auth.controller;

import io.github.fabiodelabruna.ms.core.model.ApplicationUser;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
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
@Api("Endpoints to manage User's information")
public class UserInfoController {

    @GetMapping(path = "/info", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ApiOperation(value = "Will retrieve the information from the user available in the token", response = ApplicationUser.class)
    public ResponseEntity<ApplicationUser> getUserInfo(final Principal principal) {
        final ApplicationUser user = (ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

}
