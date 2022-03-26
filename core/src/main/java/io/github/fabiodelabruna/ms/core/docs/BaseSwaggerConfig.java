package io.github.fabiodelabruna.ms.core.docs;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

@AllArgsConstructor
public class BaseSwaggerConfig {

    private final String basePackage;

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage(basePackage))
                .build()
                .apiInfo(metadata());
    }

    private ApiInfo metadata() {
        return new ApiInfoBuilder()
                .title("Spring Boot Microservices")
                .description("Project to study the microservices architecture with Spring")
                .version("1.0")
                .contact(new Contact("Fabio Dela Bruna", "https://github.com/fabiodelabruna", "fabiodelabruna@gmail.com"))
                .build();
    }

}
