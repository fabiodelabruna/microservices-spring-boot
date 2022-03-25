package io.github.fabiodelabruna.ms.auth.security.config;

import io.github.fabiodelabruna.ms.auth.security.filter.JWTUsernamePasswordAuthenticationFilter;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.token.security.config.SecurityTokenConfig;
import io.github.fabiodelabruna.ms.token.security.token.creator.TokenCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

    private final UserDetailsService userDetailsService;

    private final TokenCreator tokenCreator;

    public SecurityCredentialsConfig(final JwtConfiguration jwtConfiguration,
                                     final @Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService,
                                     final TokenCreator tokenCreator) {
        super(jwtConfiguration);
        this.tokenCreator = tokenCreator;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.addFilter(new JWTUsernamePasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator));
        super.configure(http);
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
