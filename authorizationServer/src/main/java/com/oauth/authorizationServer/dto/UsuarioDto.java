package com.oauth.authorizationServer.dto;

import java.util.List;

public record UsuarioDto (String name,
    String lastname,
    String email,
    String username,
    String password,
    List<String>roles){
    
}
