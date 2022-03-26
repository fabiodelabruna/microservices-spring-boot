package io.github.fabiodelabruna.ms.course;

import io.github.fabiodelabruna.ms.core.property.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan("io.github.fabiodelabruna.ms")
@EntityScan({"io.github.fabiodelabruna.ms.core.model"})
@EnableConfigurationProperties(value = JwtConfiguration.class)
@EnableJpaRepositories({"io.github.fabiodelabruna.ms.core.repository"})
public class CourseApplication {

    public static void main(String[] args) {
        SpringApplication.run(CourseApplication.class, args);
    }

}
