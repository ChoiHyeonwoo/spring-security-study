package io.security.study.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity  // 웹 보안에 대한 활성화
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();  // 인가방식: 어떤 요청에도 인가를 다 받는.
        http
                .formLogin()        // FORM로그인 사용
                //.loginPage("/loginPage") //로그인 페이지 경로
                .defaultSuccessUrl("/")     // 기본 성공 url
                .failureUrl("/login")
                .usernameParameter("userId")    // id 파라미터 명
                .passwordParameter("passwd")    //password 파라미터 명
                .loginProcessingUrl("/login_proc")  // 로그인 처리 URL
                .successHandler(new AuthenticationSuccessHandler() {        //로그인 성공 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication: "+ authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {        //로그인 실패 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception: "+ e.getMessage());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .permitAll()    //로그인 페이지는 접근가능하게끔
        ;
    }
}
