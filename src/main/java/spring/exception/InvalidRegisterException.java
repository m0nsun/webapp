package spring.exception;

public class InvalidRegisterException extends RuntimeException{
    public InvalidRegisterException(String message) {
        super(message);
    }
}
