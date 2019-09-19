package com.example.springsecuritydemo.common.exception;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
public class RequestFailureException extends GlobalException {

    public RequestFailureException(String cause) {
        super(cause);
    }
}
