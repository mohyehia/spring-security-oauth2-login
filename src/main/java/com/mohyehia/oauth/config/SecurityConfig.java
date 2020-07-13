package com.mohyehia.oauth.config;

import com.mohyehia.oauth.config.security.LocalSuccessHandler;
import com.mohyehia.oauth.config.security.OAuthSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final LocalSuccessHandler localSuccessHandler;
    private final OAuthSuccessHandler oAuthSuccessHandler;

    public SecurityConfig(LocalSuccessHandler localSuccessHandler, OAuthSuccessHandler oAuthSuccessHandler) {
        this.localSuccessHandler = localSuccessHandler;
        this.oAuthSuccessHandler = oAuthSuccessHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login", "/webjars/**")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login").successHandler(localSuccessHandler)
                .and()
                .headers(headers -> headers.addHeaderWriter(new StaticHeadersWriter("X-Content-Security-Policy","script-src 'self'")))
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint("/login"))
                .and()
                .logout()
                .and()
                .oauth2Login()
                .loginPage("/login").successHandler(oAuthSuccessHandler)
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
