package com.example.SpringSecurity.services;

import com.example.SpringSecurity.model.LoginDto;
import com.example.SpringSecurity.model.Role;
import com.example.SpringSecurity.model.User;
import com.example.SpringSecurity.repository.RoleRepo;
import com.example.SpringSecurity.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {
    @Autowired
    private UserRepo userRepository;

    @Autowired
    private RoleRepo roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;
    public User registerUser(String username, String password){

        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();

        Set<Role> authorities = new HashSet<>();

        authorities.add(userRole);
        User user = new User();
        user.setAuthorities(authorities);
        user.setPassword(encodedPassword);
        user.setUsername(username);
        return userRepository.save(user);
    }

    public LoginDto loginUser(String username, String password){

        try{
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            String token = tokenService.generateJwt(auth);
            LoginDto loginDto = new LoginDto();
            loginDto.setUser(userRepository.findByUsername(username).get());
            loginDto.setToken(token);
            return loginDto;

        } catch(AuthenticationException e){
            return new LoginDto();
        }
    }
}
