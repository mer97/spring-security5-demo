package com.example.springsecuritydemo.user.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@RestController
@RequestMapping("/api/v1/user")
public class UserRestController {

    @GetMapping("/username")
    @PreAuthorize("hasAuthority('USER')")
    /**
     * 获取当前登录的用户名
     * 权限验证：
     *      当请求/api/v1/user/username接口时，判断该用户是否拥有“USER”权限。
     */
    public String getUsername(Principal principal){
        return principal.getName();
    }

}
