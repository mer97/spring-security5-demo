package com.example.springsecuritydemo.common.exception.handler;


import com.example.springsecuritydemo.common.annotation.EnumCastFailMessage;
import com.example.springsecuritydemo.common.bean.ErrorResponse;
import com.example.springsecuritydemo.common.exception.DataNotFoundException;
import com.example.springsecuritydemo.common.exception.SystemErrorException;
import com.example.springsecuritydemo.common.exception.ValueInvalidException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Api调用异常处理器。
 *
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@ControllerAdvice
public class RestExceptionHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(RestExceptionHandler.class);

    @Value("${debug}")
    private boolean isDebugMode;

    @ExceptionHandler(value = ValueInvalidException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleValueInvalidException(ValueInvalidException e) {
        return new ErrorResponse(e.getMessage());
    }

    @ExceptionHandler(value = DataNotFoundException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleDataNotFoundException(DataNotFoundException e) {
        return new ErrorResponse(e.getMessage());
    }

    @ExceptionHandler(value = InvalidFormatException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleInvalidFormatException(InvalidFormatException e) {
        Class<?> targetClass = e.getTargetType();
        EnumCastFailMessage castErrorMessage = targetClass.getAnnotation(EnumCastFailMessage.class);

        return new ErrorResponse(castErrorMessage.value());
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        String error = "";
        try {
            error = e.getBindingResult().getFieldError().getDefaultMessage();
        } catch (NullPointerException nullPointerException) {
            LOGGER.error("Get Custom Error Message Failure.", nullPointerException);
            error = "系统错误";
        }

        return new ErrorResponse(error);
    }

    @ExceptionHandler(value = MismatchedInputException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleMismatchedInputException(MismatchedInputException e) {
        if (!isDebugMode) {
            return new ErrorResponse("输入有误");
        } else {
            return new ErrorResponse(e.getMessage());
        }
    }

    @ExceptionHandler(value = SystemErrorException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleSystemErrorException(SystemErrorException e) {
        return new ErrorResponse("系统异常：" + e.getMessage());
    }
}
