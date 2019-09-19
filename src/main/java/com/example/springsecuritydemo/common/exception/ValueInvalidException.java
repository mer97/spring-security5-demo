package com.example.springsecuritydemo.common.exception;

/**
 * 无效参数异常。
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
public class ValueInvalidException extends GlobalException {

    public ValueInvalidException(String message) {
        super(message);
    }
}
