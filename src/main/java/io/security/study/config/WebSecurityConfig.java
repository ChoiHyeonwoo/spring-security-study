package io.security.study.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity  // 웹 보안에 대한 활성화
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{       // 임시 사용자 생성
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }
    
    protected void configure(HttpSecurity http) throws Exception {          //인가 먼저, 인증로직 나중.
        http                                        //인가 설정관련 시작
                /*.antMatcher("/shop/**")             //해당 경로에 대한 권한 체크를 시작
                .authorizeRequests()
                .antMatchers("/shop/login", "/shop/users/**").permitAll()       //해당 경로는 모든 사용자에 대해 허용
                .antMatchers("/shop/mypage").hasRole("USER")
                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")                      // 설정 시 구체적 경로가 먼저 오고 그것보다 큰 범위의 경로가 뒤에 오도록 한다.
                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")     // ex) /shop/admin/pay 먼저 지정후 /shop/admin/** 지정.
                .anyRequest().authenticated()*/
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
        ;
        http
                .formLogin()        // FORM로그인 사용
                //.loginPage("/loginPage") //로그인 페이지 경로
                .defaultSuccessUrl("/")     // 기본 성공 url
                .failureUrl("/login")
                .usernameParameter("userId")    // id 파라미터 명
                .passwordParameter("passwd")    //password 파라미터 명
                /*.loginProcessingUrl("/login_proc")  // 로그인 처리 URL*/
                /*.successHandler(new AuthenticationSuccessHandler() {        //로그인 성공 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication: "+ authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })*/
                .successHandler(new AuthenticationSuccessHandler() {    // 로그인 성공 핸들러 (인증 성공 이후 기존 로그인 요청했던[캐싱처리 된] URL로 이동.)
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);       // 원래 사용자가 가고자했던 요청정보가 저장되어있음.
                        String redirectUrl =  savedRequest.getRedirectUrl();                                                // 가고자 했던 URL 반환
                        httpServletResponse.sendRedirect(redirectUrl);
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

        http
                .logout()
                .logoutUrl("/logout") // 로그아웃처리
                .logoutSuccessUrl("/login") //로그아웃 성공 url
                .addLogoutHandler(new LogoutHandler() { // 추가 로그아웃 핸들러 (세션삭제, security context, 쿠키 삭제 등)
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {  // 로그아웃 성공 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")   //remember-me 쿠키 삭제
        ;
        http
                .rememberMe()
                .rememberMeParameter("remember")    // default parameter name : remember-me
                .tokenValiditySeconds(3600)         // default : 14days
                .alwaysRemember(true)               // 리멤버 미 기능 활성화 하지 않아도 항상 실행
                .userDetailsService(userDetailsService);
        ;

        http
                .sessionManagement()                // 사용자 세션 관리 시작
                .sessionFixation().changeSessionId()    //세션 고정보호 (기본 값) - 새션아이디가 따로 만들어짐.
                                                        // none : 세션고정공격에 노출됨
                                                        // migrateSession: 기존 세션에 마이그레이션.
                                                        // newSession: 별도의 세션이 따로 생성
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    // 세션 생성정책
                    // SessionCreationPolicy.ALWAYS: 항상 생성
                    // SessionCreationPolicy.If_Required: 필요시에만 생성(default)
                    // SessionCreationPolicy.Never: 생성하진 않지만 이미 존재하면 사용
                    // SessionCreationPolicy.Stateless: 생성하지않고 존재해도 사용하지 않음(JWT,,,)


                .maximumSessions(1)                 // 최대 허용 가능세션수, -1: 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false)     // 동시로그인 차단, false : 후입자 정책(default), true: 선입자 정책

                /*.invalidSessionUrl("/invalid")      // 세션이 유효하지 않을 때 이동 페이지*/
                /*.expiredUrl("/expired")             // 세션 만료시 이동 URL*/
        ;


        http
                .exceptionHandling()            // 인증, 인가예외 시작
                /*.authenticationEntryPoint(new AuthenticationEntryPoint() {  // 인증예외
                    @Override
                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })*/
                .accessDeniedHandler(new AccessDeniedHandler() {    // 인가예외
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/denied");
                    }
                })
        ;

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL); //-> 인증 객체의 저장방식을 변경 (자식스레드 메인스레드 다 공유함.)

    }
}
