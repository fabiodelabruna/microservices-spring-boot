package io.github.fabiodelabruna.ms.core.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "jwt.config")
public class JwtConfiguration {

    private String loginURL = "/login/**";

    private int expiration = 3600;
    private String type = "encrypted";
    private String privateKey = "55hfXuHTCkfgeIq2WY0kDBlx6PSo0ZDz";

    @NestedConfigurationProperty
    private Header header = new Header();

    @Getter
    @Setter
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }

}
