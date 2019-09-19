package com.example.springsecuritydemo.common.exception;

/**
 * 数据未找到异常。
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
public class DataNotFoundException extends GlobalException {

    public DataNotFoundException(String message) {
        super(message);
    }

    public DataNotFoundException(int code, String message) {
        super(code, message);
    }
}
