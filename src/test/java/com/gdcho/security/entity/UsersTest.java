package com.gdcho.security.entity;

import com.gdcho.security.QuickStartApplication;
import com.gdcho.security.common.Consts;
import com.gdcho.security.service.RoleService;
import com.gdcho.security.service.UserService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = QuickStartApplication.class)
public class UsersTest {

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;


    @Test
    public void createUser() {
        String password = passwordEncoder.encode("123456");
        Users user = Users.builder().lastLoginTime(new Date()).status(Consts.USER_ENABLE).sex(Consts.SEX_UNKNOWN)
                          .phone("12345678910").nickname("nick").username("user1").password(password).build();

        Role role = Role.builder().name("管理员").roleDesc("具有管理员权限").status(Consts.USER_ENABLE).build();

//        Set<Users> userSet = new HashSet<>();
//        userSet.add(user);


        Set<Role> roleSet = new HashSet<>();
        roleSet.add(role);
        user.setRole(roleSet);

        Users newUser = userService.createUser(user.getUsername(), user.getPassword(), user.getOpenId(),
                                               user.getPassword());

        System.out.println("newUser = " + newUser);

    }

    @Test
    public void delUser() {
        Long id = 1625020241132261376L;
        userService.deleteUserById(id);
    }

    @Test
    public void getUser() {
        Long id = 1625019759332560896L;
        Optional<Users> optionalUsers = userService.queryUserById(id);
        optionalUsers.ifPresent(System.out::println);
    }


    @Test
    public void getPerms() {
        Long id = 1625019759332560896L;

    }

}