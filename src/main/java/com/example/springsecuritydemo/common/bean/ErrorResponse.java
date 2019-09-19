package com.example.springsecuritydemo.common.bean;

/**
 * 服务执行异常的返回对象。
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
public class ErrorResponse {

    private String error;

    public ErrorResponse(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}
