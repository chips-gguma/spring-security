package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Order(1) // 두 개 이상의 필터체인을 구성할 때 순서 설정 (1 : 첫 번째...)
@EnableWebSecurity(debug = true) // 어떤 필터들을 거쳤는지 보여줌
@EnableGlobalMethodSecurity(prePostEnabled = true) // prePost로 권한 체크 수행 (admin 접근 불가)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 사용자 추가
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                .username("user2")
                        .password(passwordEncoder().encode("2222"))
                        .roles("USER")
                ).withUser(User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("3333"))
                        .roles("ADMIN"))
                ;
    }

    // 패스워드 인코더로 인코딩되지 않아 발생하는 에러 방지
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 스프링 시큐리티는 기본적으로 모든 페이지를 막아두고 시작
    // 홈페이지는 열어두고 싶음
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.antMatcher("/api/**"); // 어떤 request에 대해서 필터체인이 동작할 것인지 설정, 필터체인 여러 개 구성 가능
        http.authorizeRequests((requests) ->
                requests.antMatchers("/").permitAll() // permitAll() 모든 사람에게 접근 허용
                        .anyRequest().authenticated()
        );
        http.formLogin();
        http.httpBasic();    }
}
