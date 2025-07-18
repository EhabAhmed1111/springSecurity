package com.ihab.security.service;


import com.ihab.security.auth.AuthenticationRequest;
import com.ihab.security.auth.AuthenticationResponse;
import com.ihab.security.auth.RegisterRequest;
import com.ihab.security.config.JwtService;
import com.ihab.security.user.Role;
import com.ihab.security.user.User;
import com.ihab.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    //create user and generate token and save user in database
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        //here we generate without extra claims
        //the claims will be sub and another field we defined
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                //this to pass token i already generate from user
                .token(jwtToken)
                .build();
    }
/*
    1-Spring Security creates an unauthenticated token containing:

        Principal: The raw email string

        Credentials: The raw password string

        Authorities: Empty (not authenticated yet)

   2- The AuthenticationManager:

        Finds the appropriate AuthenticationProvider (usually DaoAuthenticationProvider)

        The provider uses the principal (email) to:
        a. Load user details from your UserDetailsService
        b. Compare the provided credentials (password) with stored credentials

        If successful, returns an authenticated token containing:

            Principal: The full UserDetails object (not just email)

            Credentials: Cleared (null) for security

            Authorities: The user's granted permissions
 */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        //principles
                        //Represents the user's identity (who they claim to be)
                        request.getEmail(),
                        //credential
                        //Represents the proof of identity (secret that verifies the claim)
                        request.getPassword())
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow(
                //here we can throw user not found and handel it throw adviceController
                //but there is no need i think because  he pass the first one which by the way we handel
                //that user not found
        );
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                //this to pass token i already generate from user
                .token(jwtToken)
                .build();
    }
}
