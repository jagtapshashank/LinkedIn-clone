package com.linkedIn.linkedIn.features.authentication.dto;

import jakarta.validation.constraints.NotBlank;

public class AuthenticationRequestBody {
    @NotBlank(message = "Email is mandotory")
    private String email;
    @NotBlank(message = "Password is mandotory")
    private String password;

    public AuthenticationRequestBody(String email, String password){
        this.email= email;
        this.password=password;
    }

    public String getEmail(){
        return email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password){
        this.password = password;
    }
}

