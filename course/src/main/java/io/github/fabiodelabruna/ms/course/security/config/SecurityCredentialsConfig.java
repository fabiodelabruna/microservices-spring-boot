package io.github.fabiodelabruna.ms.course.security.config;

import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.token.security.config.SecurityTokenConfig;
import io.github.fabiodelabruna.ms.token.security.filter.JwtTokenAuthorizationFilter;
import io.github.fabiodelabruna.ms.token.security.token.converter.TokenConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

    private final TokenConverter tokenConverter;

    public SecurityCredentialsConfig(final JwtConfiguration jwtConfiguration, final TokenConverter tokenConverter) {
        super(jwtConfiguration);
        this.tokenConverter = tokenConverter;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.addFilterAfter(new JwtTokenAuthorizationFilter(jwtConfiguration, tokenConverter), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }

}
