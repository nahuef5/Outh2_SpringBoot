package com.oauth.authorizationServer.controller;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class LoginController {
    @PostMapping("/logout")
    public String logOutOk(HttpSecurity http) throws Exception{
        http.logout().logoutSuccessUrl("login?logout")
                .deleteCookies("JSESSIONID").invalidateHttpSession(true)
                .clearAuthentication(true);
        return "login?logout";
    }
    
    @GetMapping("/login")
    public String login(){
        return "login";
    }
    @GetMapping("/logout")
    public String logOut(){
        return "logout";
    }   
}