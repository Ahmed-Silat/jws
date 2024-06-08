package com.alibou.securuty.Service;

import com.alibou.securuty.Controller.AuthenticationRequest;
import com.alibou.securuty.Controller.AuthenticationResponse;
import com.alibou.securuty.Controller.RegisterRequest;
import com.alibou.securuty.Models.Role;
import com.alibou.securuty.Repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.security.core.userdetails.User.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepo repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
//        var user = User.builder()
//                .firstname(request.getFirstname())
//                .lastname(request.getLastname())
//                .email(request.getEmail())
//                .password(passwordEncoder.encode(request.getPassword()))
//                .role(Role.USER)
//                .build();
        var user = com.alibou.securuty.Models.User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse authenticationResponse= new AuthenticationResponse();
        authenticationResponse.token  = jwtToken;
        return  authenticationResponse;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse authenticationResponse= new AuthenticationResponse();
        authenticationResponse.token  = jwtToken;
        return  authenticationResponse;
    }
}
