package io.github.fabiodelabruna.ms.core.repository;

import io.github.fabiodelabruna.ms.core.model.ApplicationUser;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

    ApplicationUser findByUsername(final String username);

}
