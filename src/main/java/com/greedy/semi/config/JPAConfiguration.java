package com.greedy.semi.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(basePackages= {"com.greedy.semi"})
@EnableJpaRepositories(basePackages="com.greedy.semi")
public class JPAConfiguration {

}
