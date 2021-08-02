package com.supportportal.repository;

import com.supportportal.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users,Long> {

    Users findUsersByUsername(String username);

    Users findUsersByEmail(String email);
}
