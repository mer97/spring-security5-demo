package com.example.springsecuritydemo.common.annotation;

import java.lang.annotation.*;

/**
 * @author LEEMER
 * Create Date: 2019-09-19
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EnumCastFailMessage {

    /**
     * 定义错误信息。
     */
    String value();
}
