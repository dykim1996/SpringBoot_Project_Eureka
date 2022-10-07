package com.greedy.semi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.greedy.semi.member.service.AuthenticationService;

@EnableWebSecurity
public class SecurityConfig {
	
	private final AuthenticationService authenticationService;

    @Autowired
    public SecurityConfig(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
        return http
        		.csrf().disable()
                .authorizeRequests()
                .mvcMatchers("/member/update", "/member/delete", "/trade/regist", "/trade/update", "/trade/delete").hasAnyAuthority("ROLE_MEMBER", "ROLE_ADMIN")
                .mvcMatchers("/**", "/member/**").permitAll()
                .and()
                    .formLogin()
                    .loginPage("/member/login")             
                    .defaultSuccessUrl("/")  
                    .failureForwardUrl("/member/loginfail")
                    .usernameParameter("memberId")
                    .passwordParameter("memberPwd")
                .and()
                    .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/member/logout"))
                    .deleteCookies("JSESSIONID")
                    .invalidateHttpSession(true)
                    .logoutSuccessUrl("/")
    			.and()
    				.build();
    }
	
	@Bean
	public AuthenticationManager authManager(HttpSecurity http) throws Exception {
	    return http.getSharedObject(AuthenticationManagerBuilder.class)
	      .userDetailsService(authenticationService)
	      .passwordEncoder(passwordEncoder())
	      .and()
	      .build();
	}

}
















