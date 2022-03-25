package io.github.fabiodelabruna.ms.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.github.fabiodelabruna.ms.core.model.ApplicationUser;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.token.security.token.creator.TokenCreator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.util.Collections.emptyList;

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JWTUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtConfiguration jwtConfiguration;

    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        log.info("Attempting authentication...");

        final ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (applicationUser == null) {
            throw new UsernameNotFoundException("Unable to retrieve the username or password");
        }

        log.info("Creating authentication object for the user '{}' and calling UserDetailsServiceImpl loadUserByUsername", applicationUser.getUsername());

        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());

        usernamePasswordAuthenticationToken.setDetails(applicationUser);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                            final FilterChain chain, final Authentication auth) {

        log.info("Authentication was successful for the user '{}', generating JWE Token", auth.getName());

        final SignedJWT signedJWT = tokenCreator.createSignedJWT(auth);
        final String encryptedToken = tokenCreator.encryptToken(signedJWT);

        log.info("Token generated successfully, adding it to the response header");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptedToken);
    }

}
