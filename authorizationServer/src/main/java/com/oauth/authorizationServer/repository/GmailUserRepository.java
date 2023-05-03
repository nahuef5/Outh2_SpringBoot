package com.oauth.authorizationServer.repository;
import com.oauth.authorizationServer.entity.GmailUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GmailUserRepository extends JpaRepository<GmailUser, Long>{
    Optional<GmailUser> findByEmail(String email);
}
