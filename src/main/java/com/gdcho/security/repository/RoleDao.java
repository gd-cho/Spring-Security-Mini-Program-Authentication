package com.gdcho.security.repository;

import com.gdcho.security.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleDao extends JpaRepository<Role, Long> {
    boolean existsByNameIgnoreCase(String name);
    Optional<Role> findByNameIgnoreCase(String name);
    Set<Role> findByUsers_Id(Long id);

}
