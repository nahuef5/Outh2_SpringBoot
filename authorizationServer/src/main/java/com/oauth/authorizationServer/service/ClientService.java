package com.oauth.authorizationServer.service;
import com.oauth.authorizationServer.dto.ClientDto;
import com.oauth.authorizationServer.dto.MessageHandler;
import com.oauth.authorizationServer.entity.Client;
import com.oauth.authorizationServer.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService implements RegisteredClientRepository{
    @Autowired
    ClientRepository repository;
    @Autowired
    PasswordEncoder passwordEncoder;
    
    private Client createClient(ClientDto dto){
        Client customer= Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requiredProofkey(dto.isRequiredProofkey())
                .build();
        return customer;
    }
    public MessageHandler saveClient(ClientDto dto){
        Client customer= createClient(dto);
        repository.save(customer);
        return new MessageHandler("Client " +customer.getClientId()+ " has been created successfully");
    }
    @Override
    public void save(RegisteredClient registeredClient) {
        
    }

    @Override
    public RegisteredClient findById(String id) {
        Client customer =  repository.findByClientId(id).orElseThrow(()->new RuntimeException("There is no a client with that id"));
        return Client.registeredClient(customer);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client customer=  repository.findByClientId(clientId).orElseThrow(()->new RuntimeException("There is no a client with that id"));
        return Client.registeredClient(customer);
        
    }
}
