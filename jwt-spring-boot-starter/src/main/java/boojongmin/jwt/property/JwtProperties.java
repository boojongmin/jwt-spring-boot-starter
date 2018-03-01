package boojongmin.jwt.property;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;


@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {
    private String type = "hma";
    private Hmc hmc = new Hmc();
    private Url url = new Url();
    private Rsa rsa = new Rsa();
    private int expire = 0;
    private Authetication authetication = new Authetication();

    @Data
    public class Rsa {
        private String privateKey;
    }

    @Data
    public class Hmc {
        private String secret = "secret";
    }

    @Data
    public class Url {
        private List<String> allow;
    }

    @Data
    public class Authetication {
        private Key key = new Key();
        @Data
        public class Key {
            private String username = "username";
            private String password = "password";
        }
    }
}


