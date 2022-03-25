package io.github.fabiodelabruna.ms.token.security.filter;

import com.nimbusds.jwt.SignedJWT;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.token.security.token.converter.TokenConverter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static io.github.fabiodelabruna.ms.token.security.util.SecurityContextUtil.setSecurityContext;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {

    protected final JwtConfiguration jwtConfiguration;

    protected final TokenConverter tokenConverter;

    @Override
    protected void doFilterInternal(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
                                    final @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String header = request.getHeader(jwtConfiguration.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();
        setSecurityContext(equalsIgnoreCase("signed", jwtConfiguration.getType()) ? validate(token) : decryptValidating(token));
        filterChain.doFilter(request, response);
    }

    @SneakyThrows
    private SignedJWT decryptValidating(final String encryptedToken) {
        final String signedToken = tokenConverter.decryptToken(encryptedToken);
        return validate(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(final String signedToken) {
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }

}
