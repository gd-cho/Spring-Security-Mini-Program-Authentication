package com.gdcho.security.repository;

import com.gdcho.security.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersDao extends JpaRepository<Users, Long> {
    boolean existsByUsernameIgnoreCase(String username);

    Optional<Users> findByOpenId(String openId);

    Optional<Users> findByOpenIdOrUnionId(String openId,
                                          @Nullable String unionId);

    Optional<Users> findByUsername(String username);

    @Query("select u from Users u where u.openId = ?1 and u.unionId = ?2")
    Optional<Users> findUsersByOpenIdAndUnionId(String openId,
                                                String unionId);

}
