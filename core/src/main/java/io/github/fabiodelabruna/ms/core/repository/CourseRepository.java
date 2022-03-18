package io.github.fabiodelabruna.ms.core.repository;

import io.github.fabiodelabruna.ms.core.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {

}
