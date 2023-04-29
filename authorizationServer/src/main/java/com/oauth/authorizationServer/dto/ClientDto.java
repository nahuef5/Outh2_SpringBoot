package com.oauth.authorizationServer.dto;
import java.util.Set;
import lombok.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClientDto{

    private String clientId;
    private String clientSecret;
    private Set<ClientAuthenticationMethod>authenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String>redirectUris;
    private Set<String> scopes;
    private boolean requiredProofkey;
}
