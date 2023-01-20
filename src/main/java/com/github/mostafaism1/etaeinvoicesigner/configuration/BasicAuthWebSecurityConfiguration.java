package com.github.mostafaism1.etaeinvoicesigner.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthWebSecurityConfiguration {
  ConfigurationReader configurationReader = FileConfigurationReader.INSTANCE;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .csrf()
      .disable()
      .authorizeRequests()
      .anyRequest()
      .authenticated()
      .and()
      .httpBasic();
    return http.build();
  }

  @Bean
  public UserDetailsService users() {
    String userName = configurationReader.getUserName();
    String encryptedPassword =
      "{bcrypt}" + configurationReader.getEncryptedPassword();
    UserDetails user = User
      .builder()
      .username(userName)
      .password(encryptedPassword)
      .roles("USER")
      .build();
    return new InMemoryUserDetailsManager(user);
  }
}
