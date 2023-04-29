package com.oauth.authorizationServer.service;

import com.oauth.authorizationServer.dto.MessageHandler;
import com.oauth.authorizationServer.dto.UsuarioDto;
import com.oauth.authorizationServer.entity.Rol;
import com.oauth.authorizationServer.entity.Usuario;
import com.oauth.authorizationServer.entity.enums.RoleType;
import com.oauth.authorizationServer.repository.RolRepository;
import com.oauth.authorizationServer.repository.UsuarioRepository;
import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {
    @Autowired
    UsuarioRepository userRepo;
    @Autowired
    RolRepository rolRepo;
    @Autowired
    PasswordEncoder passwordEncoder;
    
    public MessageHandler create(UsuarioDto dto){
        Usuario user= Usuario.builder()
                .name(dto.name())
                .lastname(dto.lastname())
                .email(dto.email())
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Rol>roles= new HashSet<>();
        
        dto.roles().forEach(r ->{
            
            Rol rol = rolRepo.findByRol(RoleType.valueOf(r))
                .orElseThrow(()-> new RuntimeException("Role not found"));
                roles.add(rol);
                });
        
        user.setRoles(roles);
        userRepo.save(user);
        return new MessageHandler("The user "+user.getUsername() +" has been created successfully");
    }   
}