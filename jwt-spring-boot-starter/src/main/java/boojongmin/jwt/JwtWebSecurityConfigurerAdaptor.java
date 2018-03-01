package boojongmin.jwt;

import boojongmin.jwt.filter.JWTAuthenticationFilter;
import boojongmin.jwt.filter.JWTAuthorizationFilter;
import boojongmin.jwt.property.JwtProperties;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;


@EnableWebSecurity
@Configuration
@AllArgsConstructor
public class JwtWebSecurityConfigurerAdaptor extends WebSecurityConfigurerAdapter{
    private JwtProperties properties;
    private Algorithm algorithm;
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String[] allowUrls = Optional.ofNullable(properties.getUrl().getAllow()).map(x -> x.toArray(new String[x.size()])).orElse(new String[]{  });
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers(allowUrls).permitAll()
                .anyRequest().authenticated();
        http.addFilter(new JWTAuthenticationFilter(authenticationManager(), algorithm, properties));
        http.addFilter(new JWTAuthorizationFilter(authenticationManager(), algorithm));
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();

    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider(userDetailsService, passwordEncoder));
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }
}
