package boojongmin.jwt;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.annotation.PostConstruct;
import java.util.List;

@Configuration
@AllArgsConstructor
public class JwtWebMvcConfigurerAdapter extends WebMvcConfigurerAdapter {
    private UserDetailsService userDetailsService;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new UserDetailsHandlerMethodArgumentResolver(userDetailsService));
    }

    @AllArgsConstructor
    public class UserDetailsHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {
        private UserDetailsService userDetailsService;

        @Override
        public boolean supportsParameter(MethodParameter methodParameter) {
            return UserDetails.class.isAssignableFrom(methodParameter.getParameterType());
        }

        @Override
        public Object resolveArgument(MethodParameter methodParameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, WebDataBinderFactory webDataBinderFactory) throws Exception {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = (String) authentication.getPrincipal();
            return userDetailsService.loadUserByUsername(username);
        }
    }
}

