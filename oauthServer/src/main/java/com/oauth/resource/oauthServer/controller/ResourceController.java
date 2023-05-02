package com.oauth.resource.oauthServer.controller;
import com.oauth.resource.oauthServer.messageHandler.MessageHandler;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/resource-server")
public class ResourceController {
    
    @GetMapping("/user")
    public ResponseEntity<MessageHandler> user (Authentication authentication){
        return ResponseEntity.ok(new MessageHandler("Hi!! "+authentication.getName()));
    }
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<MessageHandler> admin(Authentication authentication){
        return ResponseEntity.ok(new MessageHandler("Hi!! "+authentication.getName()));
    }
}
