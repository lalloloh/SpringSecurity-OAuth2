package br.com.laironoliveira.auth_server.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityFilterConfig {
    
    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        
        //TODO: Verificar instância nula do configurer
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling((exceptionHandling) -> 
            exceptionHandling.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))    
        )
        .oauth2ResourceServer((oauth2ResourceServer) -> 
            oauth2ResourceServer.jwt(Customizer.withDefaults())
        );

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defauSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests((authorize) -> 
            authorize.anyRequest().authenticated()
        )
        .formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }
}
