package com.example.identity_service.exception;


// mã error code mình tự tạo
public enum ErrorCode {
    USER_EXISTED(1002,"User existed");

    ;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    private int code;
    private String message;

    public String getMessage() {
        return message;
    }

    public int getCode() {
        return code;
    }
}
