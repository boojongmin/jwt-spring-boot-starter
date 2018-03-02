package boojongmin.jwt.filter;

import boojongmin.jwt.property.JwtConstants;
import boojongmin.jwt.property.JwtProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@AllArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final Algorithm algorithm;
    private final JwtProperties properties;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        try {
            Map<String, String> user = new ObjectMapper() .readValue(req.getInputStream(), new TypeReference<HashMap<String, String>>(){});

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.get(properties.getAuthetication().getKey().getUsername()),
                            user.get(properties.getAuthetication().getKey().getPassword()))
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) {
        long expireMinute = properties.getExpire() == 0 ? Long.MAX_VALUE : properties.getExpire();
        Date expireDate = new Date(new Date().getTime() + (1000 * 60 * expireMinute));
        String token = JWT.create()
                .withSubject(((UserDetails)auth.getPrincipal()).getUsername())
                .withExpiresAt(expireDate)
                .sign(algorithm);
        res.addHeader(JwtConstants.JWT_HEADER, JwtConstants.JWT_PREFIX + token);
    }

}
