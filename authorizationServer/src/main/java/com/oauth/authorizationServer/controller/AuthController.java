package com.oauth.authorizationServer.controller;

import com.oauth.authorizationServer.dto.*;
import com.oauth.authorizationServer.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    @Autowired
    UsuarioService service;
    
    @PostMapping("/create")
    public ResponseEntity<MessageHandler>create(@RequestBody UsuarioDto dto){
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(dto));
    }
}
