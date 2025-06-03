package com.linkedIn.linkedIn.features.authentication.service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.linkedIn.linkedIn.features.authentication.dto.AuthenticationRequestBody;
import com.linkedIn.linkedIn.features.authentication.dto.AuthenticationResponseBody;
import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;
import com.linkedIn.linkedIn.features.authentication.repository.AuthenticationUserRepository;
import com.linkedIn.linkedIn.features.authentication.utils.EmailService;
import com.linkedIn.linkedIn.features.authentication.utils.Encoder;
import com.linkedIn.linkedIn.features.authentication.utils.JsonWebToken;

@Service
public class AuthenticationService {
    private final JsonWebToken jsonWebToken;
    private final Encoder encoder;
    private final AuthenticationUserRepository authenticationUserRepository;
    private final EmailService emailService;
    private final int durationInMinutes = 1;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public AuthenticationService(AuthenticationUserRepository authenticationUserRepository, Encoder encoder, JsonWebToken jsonWebToken, EmailService emailService){
        this.encoder = encoder;
        this.authenticationUserRepository = authenticationUserRepository;
        this.jsonWebToken = jsonWebToken;
        this.emailService = emailService;
    }

    public static String generateEmailVerificationToken(){
        SecureRandom random = new SecureRandom();
        StringBuilder token = new StringBuilder();
        for(int i=0; i<5; i++){
            token.append(random.nextInt(10));
        }
        return token.toString();
    }

    public void sendEmailVerificationToken(String email){
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && !user.get().getEmailVerified()){
            String emailVerificationToken = generateEmailVerificationToken();
            String hashedToken = encoder.encode(emailVerificationToken);
            user.get().setEmailVerificationToken(hashedToken);
            user.get().setEmailVerificationTokenExpiryDate(LocalDateTime.now().plusMinutes(durationInMinutes));
            authenticationUserRepository.save(user.get());
            String subject = "Email reset";
            String body = String.format("Only one step to take full advantage of LinkedIn. \n\n" + "Enter this code to verify your email: " + "%s\n\n" + "The code will expire in " + "%s" + " minutes.", emailVerificationToken, durationInMinutes);
            try {
                emailService.sendEmail(email, subject, body);
            } catch (Exception e) {
                logger.info("Error while sending email: {}", e.getMessage());
            }
            
        } else{
            throw new IllegalArgumentException("Email reset token failed or email is already verified.");
        }
    }

    public void validateEmailVerificationToken(String token, String email){
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && encoder.matches(token, user.get().getEmailVerificationToken()) && !user.get().getEmailVerificationTokenExpiryDate().isBefore(LocalDateTime.now())){
            user.get().setEmailVerified(true);
            user.get().setEmailVerificationToken(null);
            user.get().setEmailVerificationTokenExpiryDate(null);
            authenticationUserRepository.save(user.get());
            
        } else if (user.isPresent() && encoder.matches(token, user.get().getEmailVerificationToken()) && user.get().getEmailVerificationTokenExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Email token has expired.");
        } else{
            throw new IllegalArgumentException("Email reset token failed.");
        }
    }

    public AuthenticationResponseBody register(AuthenticationRequestBody registerRequestBody) {
        AuthenticationUser user = authenticationUserRepository.save(new AuthenticationUser(
                registerRequestBody.getEmail(), encoder.encode(registerRequestBody.getPassword())));

        String emailVerificationToken = generateEmailVerificationToken();
        String hashedToken = encoder.encode(emailVerificationToken);
        user.setEmailVerificationToken(hashedToken);
        user.setEmailVerificationTokenExpiryDate(LocalDateTime.now().plusMinutes(durationInMinutes));

        authenticationUserRepository.save(user);

        String subject = "Welcome to LinkedIn: Email Verification";
        String body = String.format("""
                Only one step to take full advantage of LinkedIn.

                Enter this code to verify your email: %s. The code will expire in %s minutes.""",
                emailVerificationToken, durationInMinutes);
        try {
            emailService.sendEmail(registerRequestBody.getEmail(), subject, body);
        } catch (Exception e) {
            logger.info("Error while sending email: {}", e.getMessage());
        }
        String authToken = jsonWebToken.generateToken(registerRequestBody.getEmail());
        return new AuthenticationResponseBody(authToken, "User registered successfully.");
    }

    public AuthenticationUser getUser(String email){
        return authenticationUserRepository.findByEmail(email).orElseThrow(()-> new IllegalArgumentException("User not found"));
    }

    public void sendPasswordResetToken(String email){
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent()){
            String passwordResetToken = generateEmailVerificationToken();
            String hashedToken = encoder.encode(passwordResetToken);
            user.get().setPasswordResetToken(hashedToken);
            user.get().setPasswordResetTokenExpiryDate(LocalDateTime.now().plusMinutes(durationInMinutes));
            authenticationUserRepository.save(user.get());
            String subject = "Password Reset";
            String body = String.format("""
                                    You requested a password reset.
                                    
                                    Enter this code to reset your password: %s. The code will expire in %s minutes.""", 
                                    passwordResetToken, durationInMinutes);
            try {
                emailService.sendEmail(email, subject, body);
            } catch (Exception e) {
                logger.info("Error while sending email: {}", e.getMessage());
            } 
        } else{
            throw new IllegalArgumentException("User not found. ");
        }
    }

    public void resetPassword(String email, String newPassword, String token){
        Optional<AuthenticationUser> user = authenticationUserRepository.findByEmail(email);
        if (user.isPresent() && encoder.matches(token, user.get().getPasswordResetToken()) && !user.get().getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())){
            user.get().setPasswordResetToken(null);
            user.get().setPasswordResetTokenExpiryDate(null);
            user.get().setPassword(encoder.encode(newPassword));
            authenticationUserRepository.save(user.get());
            
        } else if (user.isPresent() && encoder.matches(token, user.get().getPasswordResetToken()) && user.get().getPasswordResetTokenExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Password reset token has expired.");
        } else{
            throw new IllegalArgumentException("Password reset token failed.");
        }
    }

    public AuthenticationResponseBody login(AuthenticationRequestBody loginRequestBody) {
        AuthenticationUser user = authenticationUserRepository.findByEmail(loginRequestBody.getEmail()).orElseThrow(()-> new IllegalArgumentException("User not found"));
        if (!encoder.matches(loginRequestBody.getPassword(), user.getPassword())){
            throw new IllegalArgumentException("Password is incorrect");
        }
        String token = jsonWebToken.generateToken(loginRequestBody.getEmail());
        return new AuthenticationResponseBody(token, "Authentication Successful");
    }

}
