package global.gua.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import global.gua.resolver.config.ResolverProperties;

@SpringBootApplication
@EnableConfigurationProperties(ResolverProperties.class)
@EnableScheduling
public class ResolverApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResolverApplication.class, args);
    }
}
