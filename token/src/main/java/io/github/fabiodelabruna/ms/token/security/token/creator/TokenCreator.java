package io.github.fabiodelabruna.ms.token.security.token.creator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.fabiodelabruna.ms.core.model.ApplicationUser;
import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {

    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public SignedJWT createSignedJWT(final Authentication auth) {
        log.info("Starting to create the signed JWT");

        final ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        final JWTClaimsSet jwtClaimsSet = createJwtClaimsSet(auth, applicationUser);
        final KeyPair rsaKeys = generateKeyPair();

        log.info("Building JWK from the RSA Keys");

        final JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimsSet);

        log.info("Signing the token with private RSA keys");

        final RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
        signedJWT.sign(signer);

        log.info("Serialized token '{}'", signedJWT.serialize());
        return signedJWT;
    }

    public String encryptToken(final SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptToken method");

        final DirectEncrypter directEncrypter =
                new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes(StandardCharsets.UTF_8));

        final JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));

        log.info("Encrypting token with system's private keys");
        jweObject.encrypt(directEncrypter);
        log.info("Token encrypted");

        return jweObject.serialize();
    }

    private JWTClaimsSet createJwtClaimsSet(final Authentication auth, final ApplicationUser applicationUser) {
        log.info("Creating the JWTClaimsSet Object for '{}'", applicationUser);

        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList()))
                .issuer("https://fabiodelabruna.github.io")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() * jwtConfiguration.getExpiration() * 1000))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair() {
        log.info("Generating RSA 2048 bits Keys");

        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.genKeyPair();
    }

}
