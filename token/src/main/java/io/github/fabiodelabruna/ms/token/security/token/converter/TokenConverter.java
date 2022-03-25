package io.github.fabiodelabruna.ms.token.security.token.converter;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenConverter {

    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public String decryptToken(final String encryptedToken) {
        log.info("Decrypting token");

        final JWEObject jweObject = JWEObject.parse(encryptedToken);
        final DirectDecrypter directDecrypter = new DirectDecrypter(jwtConfiguration.getPrivateKey().getBytes(StandardCharsets.UTF_8));

        jweObject.decrypt(directDecrypter);
        log.info("Token decrypted, returning signed token...");

        return jweObject.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public void validateTokenSignature(final String signedToken) {
        log.info("Starting method to validate token signature...");

        final SignedJWT signedJWT = SignedJWT.parse(signedToken);
        log.info("Token parsed! Retrieving public key from signed token");

        final RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
        log.info("Public keu retrieved, validating signature...");

        if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
            throw new AccessDeniedException("Invalid token signature!");
        }

        log.info("The token has a valid signature");
    }

}
