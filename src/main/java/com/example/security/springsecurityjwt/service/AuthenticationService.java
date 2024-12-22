package com.example.security.springsecurityjwt.service;



import com.example.security.springsecurityjwt.entities.AuthenticationResponse;
import com.example.security.springsecurityjwt.entities.User;
import com.example.security.springsecurityjwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    // Register a new user
    public AuthenticationResponse register(User request) {
        // Check if the user already exists
        if (repository.findByUsername(request.getUsername()).isPresent()) {
            return new AuthenticationResponse("User already exists");
        }

        // Create and save a new user
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());
        user = repository.save(user);

        String token = jwtService.generateToken(user);
//
//        // Generate a JWT token for the user
//        String token = jwtService.generateToken(user.getUsername());
        return new AuthenticationResponse(token);
    }

    // Authenticate an existing user
    public AuthenticationResponse authenticate(User request) {
        // Authenticate the user credentials
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // Retrieve the user from the database
        Optional<User> userOptional = repository.findByUsername(request.getUsername());
        if (userOptional.isEmpty()) {
            throw new RuntimeException("Invalid username or password");
        }

        User user = userOptional.get();

        // Generate a JWT token for the authenticated user
        String token = jwtService.generateToken(user);
        return new AuthenticationResponse( token);
    }
}
