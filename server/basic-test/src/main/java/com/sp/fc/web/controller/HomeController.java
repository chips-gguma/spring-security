package com.sp.fc.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @RequestMapping("/")
    public String index() {
        return "홈페이지";
    }

    // 어떤 권한과 인증으로 접근했는지 확인
    @RequestMapping("/auth")
    public Authentication auth() {
        return SecurityContextHolder.getContext()
                .getAuthentication();
    }

    // 개인정보에 해당하는 리소스
    // user가 접근
    // user로 접근하는 사람은 user 권한 필요
    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @RequestMapping("/user")
    public SecurityMessage user() {
        return SecurityMessage.builder()
                .authentication(SecurityContextHolder.getContext().getAuthentication())
                .message("User 정보")
                .build();
    }

    // admin이 접근
    // admin으로 접근하는 사람은 admin 권한 필요
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/admin")
    public SecurityMessage admin() {
        return SecurityMessage.builder()
                .authentication(SecurityContextHolder.getContext().getAuthentication())
                .message("관리자 정보")
                .build();
    }

}
