package token;




public class ResultException extends RuntimeException {

    private static final long serialVersionUID = -7706260969045933277L;

    /**
     * 错误代码, 0 成功, -1 未指定, 向后兼容
     */
    private int errorCode;
    private String description;
    private Object errorData;

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Object getErrorData() {
        return errorData;
    }

    public void setErrorData(Object errorData) {
        this.errorData = errorData;
    }

    private ResultException(int errorCode,  String message, String description) {
        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    private ResultException(int errorCode,  String message, String description,
                            Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    public static ResultException of(int errorCode,  String message) {
        return new ResultException(errorCode, message, null);
    }

    public static ResultException of( ErrorCode errorCode) {
        return new ResultException(
                errorCode.getErrorCode(),
                errorCode.getErrorMessage(),
                errorCode.getDescription());
    }

    public ResultException description(String description) {
        this.description = description;
        return this;
    }

    public ResultException errorData(Object errorData) {
        this.errorData = errorData;
        return this;
    }

    public ResultException cause(Throwable cause) {
        return new ResultException(
                this.getErrorCode(),
                this.getMessage(),
                this.getDescription(),
                cause);
    }
}
