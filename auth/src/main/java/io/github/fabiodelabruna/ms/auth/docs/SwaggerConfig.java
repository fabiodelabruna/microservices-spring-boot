package io.github.fabiodelabruna.ms.auth.docs;

import io.github.fabiodelabruna.ms.core.docs.BaseSwaggerConfig;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {

    public SwaggerConfig() {
        super("io.github.fabiodelabruna.ms.auth.controller");
    }

}
