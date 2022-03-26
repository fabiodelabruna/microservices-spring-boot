package io.github.fabiodelabruna.ms.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;


@Getter
@Setter
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Entity
@Table(name = "application_user")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @Column(nullable = false)
    @NotNull(message = "The field 'username' is mandatory")
    private String username;

    @ToString.Exclude
    @Column(nullable = false)
    @NotNull(message = "The field 'password' is mandatory")
    private String password;

    @Builder.Default
    @Column(nullable = false)
    @NotNull(message = "The field 'role' is mandatory")
    private String role = "USER";

    public ApplicationUser(@NotNull final ApplicationUser applicationUser) {
        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();
    }

}
