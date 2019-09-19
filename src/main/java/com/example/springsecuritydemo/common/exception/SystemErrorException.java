package com.example.springsecuritydemo.common.exception;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
public class SystemErrorException extends GlobalException {

    public SystemErrorException(String message) {
        super(message);
    }

    public SystemErrorException(int errorCode, String message) {
        super(errorCode, message);
    }
}
