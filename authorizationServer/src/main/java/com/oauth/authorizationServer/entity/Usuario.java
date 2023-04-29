package com.oauth.authorizationServer.entity;
import jakarta.persistence.*;
import java.util.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Usuario implements UserDetails{
    //Attributes
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id_user;
    private String name;
    private String lastname;
    private String email;
    private String username;
    private String password;
    
    @ManyToMany(fetch=FetchType.EAGER)
    @JoinTable(name = "usuario_rol", joinColumns=@JoinColumn(name="id_user"),
            inverseJoinColumns=@JoinColumn(name="id_rol"))
    private Set<Rol>roles;
    
    private boolean expired=false;
    private boolean locked=false;
    private boolean credentialsExpired=false;
    private boolean disabled=false;

    //Coonstructor
    public Usuario(String name, String lastname, String email, String username, String password, Set<Rol> roles) {
        this.name = name;
        this.lastname = lastname;
        this.email = email;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
       return roles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !expired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return !disabled;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }
}