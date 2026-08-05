package com.openfgc.nomineeservice.web;

import com.openfgc.nomineeservice.service.DuplicateNominationException;
import com.openfgc.nomineeservice.service.NominationNotFoundException;
import com.openfgc.nomineeservice.service.NotAuthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.stream.Collectors;
import org.springframework.context.support.DefaultMessageSourceResolvable;

/**
 * Translates the service's exceptions into HTTP responses, so handlers can throw
 * a domain exception rather than assembling a status code themselves.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private record ErrorBody(String message) {
    }

    @ExceptionHandler(DuplicateNominationException.class)
    public ResponseEntity<ErrorBody> handleDuplicate(DuplicateNominationException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorBody(ex.getMessage()));
    }

    @ExceptionHandler(NotAuthorizedException.class)
    public ResponseEntity<ErrorBody> handleNotAuthorized(NotAuthorizedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorBody(ex.getMessage()));
    }

    @ExceptionHandler(NominationNotFoundException.class)
    public ResponseEntity<ErrorBody> handleNotFound(NominationNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorBody(ex.getMessage()));
    }

    /**
     * Reports which fields failed validation. The exception's own message embeds
     * the resolved method signature and binding internals, which are of no use to
     * a caller and describe the service's internals.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorBody> handleValidation(MethodArgumentNotValidException ex) {
        String fields = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + " " + error.getDefaultMessage())
                .distinct()
                .collect(Collectors.joining("; "));
        if (fields.isBlank()) {
            fields = ex.getBindingResult().getGlobalErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .distinct()
                    .collect(Collectors.joining("; "));
        }
        return ResponseEntity.badRequest()
                .body(new ErrorBody(fields.isBlank() ? "Request validation failed" : fields));
    }
}
