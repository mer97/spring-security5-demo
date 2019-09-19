package com.example.springsecuritydemo.base.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@Controller
public class BaseController {

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    /**
     * 跳转到后台首页
     * 权限验证：
     *      当请求/admin接口时，判断该用户是否拥有“ADMIN”权限。
     */
    public String adminIndex(){
        return "web/admin/index";
    }

    @GetMapping("/admin/login")
    /**
     * 跳转到后台登录页面
     */
    public String adminLogin(){
        return "web/admin/login";
    }

    @GetMapping("/")
    @PreAuthorize("hasAuthority('USER')")
    /**
     * 跳转到用户首页
     * 权限验证：
     *      当请求/接口时，判断该用户是否拥有“USER”权限（多个权限使用hasAnyAuthority）。
     */
    public String index(){
        return "web/user/index";
    }

    @GetMapping("/login")
    /**
     * 跳转到用户登录页面
     */
    public String login(){
        return "web/user/login";
    }

}
