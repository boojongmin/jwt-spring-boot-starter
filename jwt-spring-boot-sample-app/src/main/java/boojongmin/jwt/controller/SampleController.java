package boojongmin.jwt.controller;

import boojongmin.jwt.DDUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SampleController {

    @GetMapping("/user")
    public UserDetails user( UserDetails userDetails) {
        System.out.println(userDetails);
        return userDetails;
    }

    @GetMapping("/hello")
    public String hello() {
        return "world";
    }
}
