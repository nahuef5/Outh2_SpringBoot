package com.oauth.authorizationServer.controller;
import com.oauth.authorizationServer.dto.ClientDto;
import com.oauth.authorizationServer.dto.MessageHandler;
import com.oauth.authorizationServer.service.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/client")
public class ClientController {
    @Autowired
    ClientService service;
    @PostMapping("/create")
    public ResponseEntity<MessageHandler> create(@RequestBody ClientDto dto){
        return ResponseEntity.status(HttpStatus.CREATED).body(service.saveClient(dto));
        
    }
}
