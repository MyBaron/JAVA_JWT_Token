package token;

public interface ErrorCode {

    /**
     * @return 0 means success, > 0 means error.
     */
    int getErrorCode();

    /**
     * @return the error message, could not be null.
     */
    String getErrorMessage();

    /**
     * @return The detail error description, could be null.
     */
    default String getDescription() {
        return null;
    }
}
