package io.github.censodev.jauthlibdemo;

import com.vladmihalcea.hibernate.type.json.JsonType;
import io.github.censodev.jauthlibcore.CanAuth;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import javax.persistence.*;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "`user`")
@Getter
@Setter
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@TypeDef(name = "json", typeClass = JsonType.class)
public class User implements CanAuth {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;

    @CreationTimestamp
    private Instant createdAt;

    @Type(type = "json")
    @Column(columnDefinition = "json")
    private List<User.RoleEnum> roles;

    @Override
    public Object principle() {
        return id;
    }

    @Override
    public List<String> authorities() {
        return roles.stream()
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    public enum RoleEnum {
        ROLE_ADMIN,
        ROLE_MODERATOR,
    }
}
