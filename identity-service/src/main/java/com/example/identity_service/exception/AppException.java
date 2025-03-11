package com.example.identity_service.exception;


// thông báo lỗi của riêng mình
public class AppException extends RuntimeException {

    public AppException(ErrorCode exception) {
        super(exception.getMessage());
        this.exception = exception;
    }

    private ErrorCode exception;

    public ErrorCode getException() {
        return exception;
    }

    public ErrorCode getErrorCode() {
        return exception;
    }
}
