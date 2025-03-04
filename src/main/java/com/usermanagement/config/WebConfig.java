package com.usermanagement.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.usermanagement.config.security.JwtTokenProvider;
import com.usermanagement.config.security.MyUserDetailsService;

@Configuration
// Enable Pre & Post Security Annotations
@EnableWebSecurity
public class WebConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    MyUserDetailsService myUserDetailsService;

    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4200")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

    
//    @Override
//    protected void configure(HttpSecurity http) throws Exception
//    {
//        http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));
//
//        http.cors().and()
//                .authorizeRequests()
//                .antMatchers("/h2-console/**").permitAll()
//                .antMatchers("/auth/**", "/auth/login", "/api/users", "/users").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().disable()
//                .httpBasic().disable()
//                .csrf().disable()
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .headers().frameOptions().disable();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and() // Ensure CORS is enabled for security filters
            .authorizeRequests()
//            .antMatchers("/auth/**", "/auth/login", "/api/users", "/users").permitAll()
            .antMatchers("/auth/**", "/auth/login", "/api/users/**", "/users/**").permitAll() // Allow all users endpoints
            .anyRequest().authenticated()
            .and()
            .csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(13);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    

}