package com.oauth.authorizationServer.config;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.oauth.authorizationServer.federated.FederatedIdentityConfigurer;
import com.oauth.authorizationServer.federated.UserRepositoryOAuth2UserHandler;
import com.oauth.authorizationServer.repository.GmailUserRepository;
import com.oauth.authorizationServer.service.ClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.*;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import java.security.*;
import java.security.interfaces.*;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class AuthorizationConfig {
    @Autowired
    ClientService service;
    private final GmailUserRepository gmailUserRepo;
    
    @Bean
    @Order(1)
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                    .oidc(Customizer.withDefaults());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        http.apply(new FederatedIdentityConfigurer());
	return http.build();
    }
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer()
			.oauth2UserHandler(new UserRepositoryOAuth2UserHandler(gmailUserRepo));
		
        http.authorizeHttpRequests(authorizeRequests ->
		authorizeRequests
				.requestMatchers("/auth/**", "/client/**", "/login").permitAll()
				.anyRequest().authenticated())
                
            .formLogin(Customizer.withDefaults())
            .apply(federatedIdentityConfigurer);
        http.csrf().ignoringRequestMatchers("/auth/**", "/client/**");
	return http.build();
    }
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
        return context ->{
            Authentication principal = context.getPrincipal();
            if(context.getTokenType().getValue().equals("id_token")){
                context.getClaims().claim("tokenType", "id_token");
            }
            if(context.getTokenType().getValue().equals("access_token")){
                context.getClaims().claim("tokenType", "access_token");
                Set<String> roles=principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("roles", roles);
            }
        };
    }
     @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    @Bean
    public OAuth2AuthorizationService authorizationService(){
        return new InMemoryOAuth2AuthorizationService();
    }
    
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(){
        return new InMemoryOAuth2AuthorizationConsentService();
    }
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().issuer("http://localhost:5050").build();
    }
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
    
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
    private RSAKey generateRSAKey(){
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }
    private KeyPair generateKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return keyPair;
    }   
}