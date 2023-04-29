package com.oauth.authorizationServer.repository;
import com.oauth.authorizationServer.entity.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository <Client, Integer>{
    Optional<Client>findByClientId(String clientId);
    
}
