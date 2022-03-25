package io.github.fabiodelabruna.ms.gateway.security.config;

import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.gateway.security.filter.GatewayJwtTokenAuthorizationFilter;
import io.github.fabiodelabruna.ms.token.security.config.SecurityTokenConfig;
import io.github.fabiodelabruna.ms.token.security.token.converter.TokenConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends SecurityTokenConfig {

    private final TokenConverter tokenConverter;

    public SecurityConfig(final JwtConfiguration jwtConfiguration, final TokenConverter tokenConverter) {
        super(jwtConfiguration);
        this.tokenConverter = tokenConverter;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.addFilterAfter(new GatewayJwtTokenAuthorizationFilter(jwtConfiguration, tokenConverter), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }

}
