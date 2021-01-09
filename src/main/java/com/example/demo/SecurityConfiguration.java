package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//this indicates to the compiler that the file is a configuration file and Spring Security
//is enabled for the application

@Configuration
@EnableWebSecurity
//SecurityConfiguration extends the WebSecurityConfigureAdapter which hass all the methods needed to include security
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private SSUserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetailsService userDetailsServiceBean() throws
            Exception{
        return new SSUserDetailsService(userRepository);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //restricts access to routes
        http

                .authorizeRequests() //tells application which requests should be authorized
                .antMatchers("/", "/h2-console/**", "/register").permitAll()
                .antMatchers("/admin")
                .access("hasAnyAuthority('USER','ADMIN')")
                .antMatchers("/admin").access("hasAuthority('ADMIN')")
                .anyRequest().authenticated()
                .and() //adds additional authentication rules; combine rules
                //indicates that application should show a login form; springboots default page
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .permitAll()
                .permitAll()
                .and()
                .httpBasic();
        http
                .csrf().disable();
        http
                .headers().frameOptions().disable();
    }
//configures users who can access the application/how users are granted access
    @Override
    protected void configure(AuthenticationManagerBuilder auth)
        throws Exception {

        auth.userDetailsService(userDetailsServiceBean())
                .passwordEncoder(passwordEncoder());

//        auth.inMemoryAuthentication()
//                .withUser("dave").password(passwordEncoder().encode("begreat"))
//                .authorities("ADMIN")
//
//                .and()
//                .withUser("user").password(passwordEncoder().encode("password"))
//                .authorities("USER");
//    }
    }

}
