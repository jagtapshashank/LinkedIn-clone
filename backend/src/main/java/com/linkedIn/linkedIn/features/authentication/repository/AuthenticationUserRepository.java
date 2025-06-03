package com.linkedIn.linkedIn.features.authentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;

import java.util.Optional;

public interface AuthenticationUserRepository extends JpaRepository<AuthenticationUser, Long>{
    Optional<AuthenticationUser> findByEmail(String email);
}