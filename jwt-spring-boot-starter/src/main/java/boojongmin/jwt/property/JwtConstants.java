package boojongmin.jwt.property;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;

public class JwtConstants {
    public static final String JWT_SECRET = "secret";
    public static final String JWT_HEADER = "Authorization";
    public static final String JWT_PREFIX = "Bearer ";
    public static final String JWT_AUTHORITIES_KEY = "ROLE";
    public static final List<SimpleGrantedAuthority> JWT_AUTHS = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"));
}
