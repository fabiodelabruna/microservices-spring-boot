package io.github.fabiodelabruna.ms.gateway.security.filter;

import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import io.github.fabiodelabruna.ms.token.security.filter.JwtTokenAuthorizationFilter;
import io.github.fabiodelabruna.ms.token.security.token.converter.TokenConverter;
import io.github.fabiodelabruna.ms.token.security.util.SecurityContextUtil;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class GatewayJwtTokenAuthorizationFilter extends JwtTokenAuthorizationFilter {

    public GatewayJwtTokenAuthorizationFilter(final JwtConfiguration jwtConfiguration, final TokenConverter tokenConverter) {
        super(jwtConfiguration, tokenConverter);
    }

    @Override
    @SneakyThrows
    @SuppressWarnings("duplicates")
    protected void doFilterInternal(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
                                    final @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String header = request.getHeader(jwtConfiguration.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();
        final String signedToken = tokenConverter.decryptToken(token);
        tokenConverter.validateTokenSignature(signedToken);

        SecurityContextUtil.setSecurityContext(SignedJWT.parse(signedToken));

        if (StringUtils.equalsIgnoreCase("signed", jwtConfiguration.getType())) {
            RequestContext.getCurrentContext().addZuulRequestHeader("Authorization", jwtConfiguration.getHeader().getPrefix().concat(signedToken));
        }

        filterChain.doFilter(request, response);
    }

}
