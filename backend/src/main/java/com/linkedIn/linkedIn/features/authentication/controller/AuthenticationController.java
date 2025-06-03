package com.linkedIn.linkedIn.features.authentication.controller;

import java.io.UnsupportedEncodingException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.linkedIn.linkedIn.features.authentication.dto.AuthenticationRequestBody;
import com.linkedIn.linkedIn.features.authentication.dto.AuthenticationResponseBody;
import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;
import com.linkedIn.linkedIn.features.authentication.service.AuthenticationService;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;



@RestController
@RequestMapping("/api/v1/authentication")
public class AuthenticationController {

    private final AuthenticationService authenticationUserService;
    public AuthenticationController(AuthenticationService authenticationUserService){
        this.authenticationUserService = authenticationUserService;
    }

    @GetMapping("/user")
    public AuthenticationUser getUser(@RequestAttribute("authenticatedUser")AuthenticationUser user){
        return user;
    }

    @PostMapping("/login")
    public AuthenticationResponseBody loginPage(@Valid @RequestBody AuthenticationRequestBody loginRequestBody) {
        return authenticationUserService.login(loginRequestBody);
    }

    @PostMapping("/register")
    public AuthenticationResponseBody registerPage(@Valid @RequestBody AuthenticationRequestBody registerRequestBody) throws UnsupportedEncodingException, MessagingException {
        return authenticationUserService.register(registerRequestBody);
    }

    @PutMapping("/validate-email-verification-token")
    public String verfiyEmail(@RequestParam String token, @RequestAttribute("authenticatedUser") AuthenticationUser user) {
        authenticationUserService.validateEmailVerificationToken(token, user.getEmail());
        return "Email verified successfully. ";
    }

    @GetMapping("/send-email-verification-token")
    public String sendEmailVerificationToken(@RequestAttribute("authenticatedUser") AuthenticationUser user) {
        authenticationUserService.sendEmailVerificationToken(user.getEmail());
        return "Email verification token sent successfully. ";
    }

    @PutMapping("/send-password-reset-token")
    public String sendPasswordResetToken(@RequestParam String email) {
        authenticationUserService.sendPasswordResetToken(email);
        return "Password Reset Token sent successfully. ";
    }

    @PutMapping("/reset-password")
    public String resetPassword(@RequestParam String newPassword, @RequestParam String token, @RequestParam String email) {
        authenticationUserService.resetPassword(email, newPassword, token);
        return "Password reset successfully. ";
    }
    
    
}
