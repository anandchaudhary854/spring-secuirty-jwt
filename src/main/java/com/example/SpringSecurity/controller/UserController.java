package com.example.SpringSecurity.controller;

import com.example.SpringSecurity.model.LoginDto;
import com.example.SpringSecurity.model.RegisterDto;
import com.example.SpringSecurity.model.User;
import com.example.SpringSecurity.services.AuthService;
import com.example.SpringSecurity.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    UserService userService;

    @Autowired
    AuthService authService;

    @GetMapping("/user")
    public String user(){
        return "This is for user";
    }

    @GetMapping("/admin")
    public String admin(){
        return "This is for admin";
    }

    @PostMapping("/auth/registerUser")
    public User registerUser(@RequestBody RegisterDto registerDto){
        return authService.registerUser(registerDto.getUsername(), registerDto.getPassword());
    }

    @PostMapping("/auth/login")
    public LoginDto login(@RequestBody RegisterDto registerDto){
        return authService.loginUser(registerDto.getUsername(), registerDto.getPassword());
    }
}
