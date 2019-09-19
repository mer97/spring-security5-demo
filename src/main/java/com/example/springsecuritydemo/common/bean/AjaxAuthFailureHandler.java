package com.example.springsecuritydemo.common.bean;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义验证失败处理器。
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@Component
public class AjaxAuthFailureHandler implements AuthenticationFailureHandler {
    private ObjectMapper objectMapper;

    public AjaxAuthFailureHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        ErrorResponse errorResponse = new ErrorResponse("用户名或密码错误");
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.getOutputStream().write(objectMapper.writeValueAsBytes(errorResponse));

    }
}
