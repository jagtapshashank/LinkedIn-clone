package com.linkedIn.linkedIn.features.authentication.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;
import com.linkedIn.linkedIn.features.authentication.service.AuthenticationService;
import com.linkedIn.linkedIn.features.authentication.utils.JsonWebToken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthenticationFilter extends HttpFilter{
    private final List<String> unsecuredEndpoints = Arrays.asList(
        "/api/v1/authentication/login",
        "/api/v1/authentication/register",
        "/api/v1/authentication/send-password-reset-token",
        "/api/v1/authentication/reset-password"
    );

    private final JsonWebToken jsonWebTokenService;
    private final AuthenticationService authenticationService;

    public AuthenticationFilter(JsonWebToken jsonWebTokenService, AuthenticationService authenticationService){
        this.jsonWebTokenService = jsonWebTokenService;
        this.authenticationService = authenticationService;
    };

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())){
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        String path = request.getRequestURI();

        if (unsecuredEndpoints.contains(path)){
            chain.doFilter(request, response);
            return;
        }

        try{
            String authorization = request.getHeader("Authorization");

            if (authorization == null || !authorization.startsWith("Bearer ")){
                throw new ServletException("Tokken missing");
            }

            String token = authorization.substring(7);

            if (jsonWebTokenService.isTokenExpired(token)){
                throw new ServletException("Invalid token");
            }

            String email = jsonWebTokenService.getEmailFromToken(token);
            AuthenticationUser user = authenticationService.getUser(email);
            // Auth logic
            request.setAttribute("authenticatedUser", user);
            // Pass request to controller
            chain.doFilter(request, response);

        }catch(Exception e){
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\": \"Invalid authentication token, or token missing.\"}");
        }

    };

}
