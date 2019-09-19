package com.example.springsecuritydemo.user.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@Controller
@RequestMapping("/api/v1/user")
public class PageController {

    @GetMapping("")
    @PreAuthorize("hasAuthority('USER_LIST')")
    public String toUserPage(){
        return "/web/user/list";
    }

}
