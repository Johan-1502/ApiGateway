package co.edu.uptc.apigateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {

        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(ServerHttpSecurity.CorsSpec::disable)
            .authorizeExchange(auth -> auth
                .pathMatchers("/login/**").permitAll()
                .pathMatchers("/actuator/**").permitAll()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt ->
                    jwt.jwtDecoder(NimbusReactiveJwtDecoder.withSecretKey(
                        new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256")
                    ).build())
                )
            );

        return http.build();
    }
}


/*
//FUNCIONANDO SIN TOKEN

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> {})

                .authorizeExchange(exchange -> exchange
                        .anyExchange().permitAll()
                )

                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        ;

        return http.build();
    }
}

*/
