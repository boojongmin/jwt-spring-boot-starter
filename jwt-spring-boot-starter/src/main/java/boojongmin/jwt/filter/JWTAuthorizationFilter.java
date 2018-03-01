package boojongmin.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static boojongmin.jwt.property.JwtConstants.JWT_AUTHS;
import static boojongmin.jwt.property.JwtConstants.JWT_HEADER;
import static boojongmin.jwt.property.JwtConstants.JWT_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private JWTVerifier verifier;
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, Algorithm algorithm) {
        super(authenticationManager);
        this.verifier = JWT.require(algorithm)
//                .withIssuer("auth0")
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(JWT_HEADER);

        if (header == null || !header.startsWith(JWT_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(JWT_HEADER);
        if (token != null) {
            try {
                DecodedJWT decodedJWT = verifier.verify(token.replace(JWT_PREFIX, ""));
                String username = decodedJWT.getSubject();
                if (username != null) {
                    return new UsernamePasswordAuthenticationToken(username, null, JWT_AUTHS);
                }
            } catch (JWTVerificationException e) {
                e.printStackTrace();
            }
            return null;
        }
        return null;
    }

}

