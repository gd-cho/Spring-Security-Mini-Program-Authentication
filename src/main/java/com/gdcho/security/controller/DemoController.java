package com.gdcho.security.controller;

import com.gdcho.security.common.APIResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/")
public class DemoController {

    @GetMapping
    public APIResponse<String> abc() {
        System.out.println("666");
        return APIResponse.ofSuccess("welcome to home!");
    }

    @GetMapping("hello")
    public APIResponse<String> hello(HttpServletRequest req) throws ServletException, IOException {

        try {
            System.out.println("req.getRequestURI() = " + req.getRequestURI());
            System.out.println("req.getAuthType() = " + req.getAuthType());
            System.out.println("req.getContextPath() = " + req.getContextPath());
            System.out.println("req.getMethod() = " + req.getMethod());
            System.out.println("req.getRemoteUser() = " + req.getRemoteUser());
            System.out.println("req.getServletPath() = " + req.getServletPath());
            System.out.println("req.getQueryString() = " + req.getQueryString());
            System.out.println("req.getRequestURL() = " + req.getRequestURL());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return APIResponse.ofSuccess("hello!");
    }


    @GetMapping("/home")
    public APIResponse<String> home() {
        return APIResponse.ofSuccess("homier");
    }

    @GetMapping("/ignore1")
    public APIResponse<String> ignore() {
        return APIResponse.ofSuccess("ignore1");
    }


    @GetMapping("/fool1")
    @PreAuthorize("@rs.hasPerm('sys:user:view')")
    public APIResponse<String> fool() {
        return APIResponse.ofSuccess("you are fool1!");
    }

    @GetMapping("/fool2")
    @PreAuthorize("@rs.hasPerm('sys:user:query')")
    public APIResponse<String> fool2() {
        return APIResponse.ofSuccess("you are fool2!");
    }

}
