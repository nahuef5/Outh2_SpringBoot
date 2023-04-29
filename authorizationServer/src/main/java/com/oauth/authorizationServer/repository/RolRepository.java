package com.oauth.authorizationServer.repository;
import com.oauth.authorizationServer.entity.Rol;
import com.oauth.authorizationServer.entity.enums.RoleType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolRepository extends JpaRepository<Rol, Integer>{
    Optional<Rol>findByRol(RoleType roleType);
}
