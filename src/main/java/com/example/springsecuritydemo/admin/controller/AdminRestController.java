package com.example.springsecuritydemo.admin.controller;

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
@RequestMapping("/admin/api/v1/user")
public class AdminRestController {

    @GetMapping("/username")
    @PreAuthorize("hasAuthority('ADMIN')")
    /**
     * 获取当前登录的用户名
     * 权限验证：
     *      当请求/api/v1/admin/username接口时，判断该用户是否拥有“ADMIN”权限。
     */
    public String getUsername(Principal principal){
        return principal.getName();
    }

}
