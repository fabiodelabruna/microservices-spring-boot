package io.github.fabiodelabruna.ms.course.service;

import io.github.fabiodelabruna.ms.core.model.Course;
import io.github.fabiodelabruna.ms.core.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CourseService {

    private final CourseRepository courseRepository;

    public Iterable<Course> list(final Pageable pageable) {
        log.info("Listing all courses");
        return courseRepository.findAll(pageable);
    }

}
