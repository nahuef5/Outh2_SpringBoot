package com.oauth.authorizationServer.entity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.oauth2.core.user.OAuth2User;
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GmailUser {
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id_user;
    private String email;
    private String name;
    private String givenName;
    private String familyName;
    private String pictureUrl;
    
    public static GmailUser fromOAuth2User(OAuth2User user){
        GmailUser gmailUser= GmailUser.builder()
                .email(user.getName())
                .name(user.getAttributes().get("name").toString())
                .givenName(user.getAttributes().get("given_name").toString())
                .familyName(user.getAttributes().get("family_name").toString())
                .pictureUrl(user.getAttributes().get("picture").toString())
                .build();

        return gmailUser;
    }   
}