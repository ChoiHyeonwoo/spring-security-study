package io.security.study.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/loginPage")   //커스텀 로그인 앤드포인트
    public String loginPage(){
        return "loginPage";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }
}
