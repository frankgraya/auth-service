package com.frank.authservice;


import com.frank.authservice.model.RegisterRequest;
import com.frank.authservice.model.User;
import com.frank.authservice.repository.UserRepository;
import com.frank.authservice.security.JwtUtil;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService  {


    private final UserRepository repository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder encoder;

    public AuthService (UserRepository repository, JwtUtil jwtUtil, PasswordEncoder encoder) {
        this.repository = repository;
        this.jwtUtil = jwtUtil;
        this.encoder = encoder;
    }

    public String login(String email, String password) {
        User user = repository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        if (!encoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        return jwtUtil.generateToken(user);
    }


    public void registerUser(RegisterRequest request) {
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("El email ya está registrado.");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(encoder.encode(request.getPassword())); // Importante: encriptar contraseña
        user.setRole(request.getRole());
        repository.save(user);
  }

    public List<User> getAllUsers() {
        return repository.findAll();
    }

}
