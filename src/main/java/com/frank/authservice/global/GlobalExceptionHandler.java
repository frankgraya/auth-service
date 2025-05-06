package com.frank.authservice.global;

import com.frank.authservice.security.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


/**
 * Clase encargada de manejar excepciones de forma global en los controladores REST.
 * Utiliza @RestControllerAdvice para interceptar excepciones lanzadas por cualquier @RestController.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {



    /**
     * Maneja excepciones del tipo MethodArgumentNotValidException,
     * que se lanzan cuando falla una validación en un método con @Valid (por ejemplo, DTOs mal formateados).
     *
     * @param ex la excepción capturada que contiene los errores de validación
     * @return un ResponseEntity con un mapa donde la clave es el nombre del campo y el valor es el mensaje de error,
     *         junto con un código HTTP 400 (BAD_REQUEST)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();

        // Itera sobre cada error de campo y lo agrega al mapa
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        // Devuelve los errores en el cuerpo con el estado 400
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(org.springframework.security.access.AccessDeniedException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "No tienes permisos suficientes para acceder a este recurso.");
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN); // 403
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(io.jsonwebtoken.ExpiredJwtException.class)
    public ResponseEntity<Map<String, String>> handleExpiredToken(ExpiredJwtException ex) {
        Map<String, String> error = new HashMap<>();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.of("America/Mexico_City"));
        error.put("error", "El token ha expirado, por favor inicia sesión nuevamente.");
        error.put("emitido", formatter.format(ex.getClaims().getIssuedAt().toInstant()));
        error.put("expira", formatter.format(ex.getClaims().getExpiration().toInstant()));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }


}
