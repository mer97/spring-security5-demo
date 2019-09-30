package com.example.springsecuritydemo.common.security.config;

import com.example.springsecuritydemo.common.bean.AjaxAuthFailureHandler;
import com.example.springsecuritydemo.common.bean.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * 用户页面认证、授权
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@Configuration
@Order(2)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class UserSecurityConfig extends WebSecurityConfigurerAdapter {

    private static Map<String, String> USER_MAP = new HashMap();

    /**
     * 模拟数据库用户名和密码(使用md5加密)
     */
    static {
        USER_MAP.put("zhangsan", DigestUtils.md5Hex("123456"));
        USER_MAP.put("lisi", DigestUtils.md5Hex("123456"));
    }

    /**
     * json 格式装换类
     */
    private ObjectMapper objectMapper;

    /**
     * ajax请求失败处理器。
     */
    private AjaxAuthFailureHandler ajaxAuthFailureHandler;

    @Autowired
    public UserSecurityConfig(ObjectMapper objectMapper,
                                AjaxAuthFailureHandler ajaxAuthFailureHandler) {
        this.objectMapper = objectMapper;
        this.ajaxAuthFailureHandler = ajaxAuthFailureHandler;

    }

    /**
     * 配置以MD5验证密码。
     * @return
     */
    @Bean
    @Order(1)
    public PasswordEncoder md5PasswordEncoderForTenancyUser() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(encode(rawPassword));
            }
        };
    }

    /**
     * 验证用户名、密码和授权。
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetailsService userDetailsService() throws UsernameNotFoundException {
        return (username) -> {
            if (USER_MAP.get(username) == null) {
                throw new UsernameNotFoundException("User Not Found: " + username);
            }
            /**
             * 用户授权，用户名为lisi的拥有访问用户列表的权限
             */
            List simpleGrantedAuthorities = new ArrayList<>();
            if ("lisi".equals(username)){
                simpleGrantedAuthorities.add(new SimpleGrantedAuthority("USER_LIST"));
            }
            simpleGrantedAuthorities.add(new SimpleGrantedAuthority("USER"));
            return User.withUsername(username)
                    .password(USER_MAP.get(username))
                    .authorities(simpleGrantedAuthorities)
                    .build();
        };
    }

    /**
     * 配置自定义验证用户名、密码和授权的服务。
     * @param authenticationManagerBuilder
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder)
            throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService());
    }

    /**
     * http请求配置：
     *      1.开启权限拦截路径。
     *      2.释放资源配置。
     *      3.登录请求配置。
     *      4.退出登录配置。
     *      5.默认开启csrf防护。
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(unauthorizedEntryPoint())
                .accessDeniedHandler(handleAccessDeniedForUser())
                .and()
        .headers()
                .frameOptions()
                .disable()
                .and()
         .authorizeRequests()
                .antMatchers("/public/**","/login")
                .permitAll()
                .anyRequest()
                .hasAuthority("USER")
                .and()
         .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/api/v1/login")
                .permitAll()
                .defaultSuccessUrl("/")
                .successHandler(ajaxAuthSuccessHandler())
                .failureHandler(ajaxAuthFailureHandler)
                .and()
         .logout()
                .logoutUrl("/api/v1/logout")
                .logoutSuccessHandler(ajaxLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");
    }

    /**
     * 判断是否ajax请求，是ajax请求则返回json，否则跳转失败页面。
     * @return
     */
    private AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) -> {
            String requestedWithHeader = request.getHeader("X-Requested-With");
            if ("XMLHttpRequest".equals(requestedWithHeader)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getOutputStream().write(authException.getMessage().getBytes());
            } else {
                response.sendRedirect("/login");
            }
        };
    }

    /**
     * 自定义登录成功处理器。
     * @return
     */
    private AuthenticationSuccessHandler ajaxAuthSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");

            ObjectNode root = objectMapper.createObjectNode();
            root.put("redirect",
                    request.getRequestURI().equals("/api/v1/login") ? "/" : request.getRequestURI());

            response.getOutputStream().write(root.toString().getBytes());
        };
    }

    /**
     * 自定义登录成功处理器。
     * @return
     */
    private LogoutSuccessHandler ajaxLogoutSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            ObjectNode root = objectMapper.createObjectNode();
            root.put("redirect", "/login");

            response.getOutputStream().write(root.toString().getBytes());
        };
    }

    /**
     * 自定义AccessDeniedHandler来处理Ajax请求。
     * @return
     */
    private AccessDeniedHandler handleAccessDeniedForUser() {
        return (HttpServletRequest request,
                HttpServletResponse response,
                AccessDeniedException accessDeniedException) -> {
            String requestedWithHeader = request.getHeader("X-Requested-With");
            if ("XMLHttpRequest".equals(requestedWithHeader)) {
                ErrorResponse errorResponse = new ErrorResponse(accessDeniedException.getMessage());
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getOutputStream().write(objectMapper.writeValueAsBytes(errorResponse));
            } else {
                response.sendRedirect("/login");
            }
        };
    }
}

