package com.example.identity_service.service;

import com.example.identity_service.dto.request.AuthenticationRequest;
import com.example.identity_service.dto.request.IntrospectRequest;
import com.example.identity_service.dto.response.AuthenticationResponse;
import com.example.identity_service.dto.response.IntrospectResponse;
import com.example.identity_service.exception.AppException;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String  SIGNER_KEY;

    // Phương thức kiểm tra (introspect) tính hợp lệ của access token
    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {

        // Lấy token từ request
        var token = request.getToken();

        // Tạo đối tượng JWSVerifier sử dụng khóa bí mật (SIGNER_KEY)
        // MACVerifier sử dụng thuật toán HMAC để xác minh token
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        // Phân tích (parse) token dạng JWT đã ký thành đối tượng SignedJWT
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Lấy thời gian hết hạn của token
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        // Xác minh token có hợp lệ với khóa SIGNER_KEY không (chữ ký đúng không)
        var verified = signedJWT.verify(verifier);

        // Trả về kết quả introspection: token hợp lệ nếu (1) verify chữ ký thành công và (2) chưa hết hạn
        return IntrospectResponse.builder()
                .valid(verified && expiryTime.after(new Date())) // true nếu token hợp lệ và còn hạn
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) throws JOSEException {
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());

        if (!authenticated)
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        var token = generateToken(request.getUsername());

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

    private String generateToken(String username) throws JOSEException {
        //tạo header truyền vào thuật toán mã hóa
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512);

        // tạo body cho playload
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer("identity-service")
                .subject(username)
                .issueTime( new Date())
                .expirationTime(new Date(Instant.now().plus(1, ChronoUnit.DAYS).toEpochMilli()))
                .build();

        // tạo payload
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        // tạo object
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);



        // ký token
        try{
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }

    }
}
