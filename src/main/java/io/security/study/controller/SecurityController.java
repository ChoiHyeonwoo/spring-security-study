package io.security.study.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index(HttpSession session){

        /**
         * authentication을 get 하는 두가지.(결국 동일하다.)
         */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();     // SecurityContextHolder에서 get

        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY); // HttpSession에서 get
        Authentication authentication1 = context.getAuthentication();

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

    @GetMapping("/denied")
    public String denied(){
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

}
