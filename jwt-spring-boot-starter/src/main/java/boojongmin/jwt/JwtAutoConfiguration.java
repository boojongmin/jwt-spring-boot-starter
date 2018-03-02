package boojongmin.jwt;

import boojongmin.jwt.example.SimpleUserDetailsService;
import boojongmin.jwt.property.JwtProperties;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
@Import(value= {JwtWebSecurityConfigurerAdaptor.class, JwtWebMvcConfigurerAdapter.class})
@AllArgsConstructor
public class JwtAutoConfiguration {
    private JwtProperties properties;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Algorithm jwtAlgorithm() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        if(properties.getType().equals("rsa")) {
            if( properties.getRsa().getPrivateKey() == null) throw new InvalidAlgorithmParameterException();

            String privateKeyStr = properties.getRsa().getPrivateKey();
            PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyStr.getBytes())));
            Security.addProvider(new BouncyCastleProvider());

            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            byte[] content = pemReader.readPemObject().getContent();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
            RSAPrivateKey privateKey = (RSAPrivateKey)factory.generatePrivate(privateKeySpec);
            RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
            RSAPublicKey publicKey = (RSAPublicKey)factory.generatePublic(publicKeySpec);

            return Algorithm.RSA256(publicKey, privateKey);
        } else {
            String secret = Optional.ofNullable(properties.getHmc()).map(x -> x.getSecret()).orElse("secret");
            return Algorithm.HMAC256(secret);
        }
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new SimpleUserDetailsService();
    }
}
