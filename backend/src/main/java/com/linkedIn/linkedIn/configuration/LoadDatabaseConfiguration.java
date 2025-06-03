package com.linkedIn.linkedIn.configuration;


import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;
import com.linkedIn.linkedIn.features.authentication.repository.AuthenticationUserRepository;
import com.linkedIn.linkedIn.features.authentication.utils.Encoder;

@Configuration
public class LoadDatabaseConfiguration {
    private final Encoder encoder;

    public LoadDatabaseConfiguration(Encoder encoder){
        this.encoder = encoder;
    }

    @Bean
    public CommandLineRunner initDatabase (AuthenticationUserRepository authenticationUserRepository){
        return args -> {
            AuthenticationUser authenticationUser = new AuthenticationUser("shashank@example.com", encoder.encode("shashank"));

            authenticationUserRepository.save(authenticationUser);
        };
    }
}
