package com.oauth.authorizationServer.entity;

import jakarta.persistence.*;
import java.util.Date;
import java.util.Set;
import lombok.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "`client`")
public class Client {
    
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private int id;
    private String clientId;
    private String clientSecret;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod>authenticationMethods;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String>redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;

    private boolean requiredProofkey;
    
    public static RegisteredClient registeredClient(Client client){
        RegisteredClient.Builder builder= RegisteredClient
                .withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(authMet -> authMet
                        .addAll(client.getAuthenticationMethods()))
                .authorizationGrantTypes(authGrTy -> authGrTy.addAll(client.getAuthorizationGrantTypes()))
                .redirectUris(redUris -> redUris.addAll(client.getRedirectUris()))
                .scopes(scope -> scope.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequiredProofkey()).build());
        return builder.build();
    }
}