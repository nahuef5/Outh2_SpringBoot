package com.oauth.authorizationServer.entity;

import com.oauth.authorizationServer.entity.enums.RoleType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Rol implements GrantedAuthority{
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private int id_rol;
    @Enumerated(EnumType.STRING)
    private RoleType rol;

    @Override
    public String getAuthority() {
        return rol.name();
    }
}