package com.oauth.authorizationServer.federated;
import com.oauth.authorizationServer.entity.GmailUser;
import com.oauth.authorizationServer.repository.GmailUserRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {
    private final GmailUserRepository gmailUserRepository;
    
    @Override
    public void accept(OAuth2User userOAuth) {
        if (!this.gmailUserRepository.findByEmail(userOAuth.getName()).isPresent()) {
            GmailUser gUser= GmailUser.fromOAuth2User(userOAuth);
            log.info(gUser.toString());
            this.gmailUserRepository.save(gUser);
	}
        else {
            log.info("Welcome {}", userOAuth.getAttributes().get("given_name"));
        }
    }
}