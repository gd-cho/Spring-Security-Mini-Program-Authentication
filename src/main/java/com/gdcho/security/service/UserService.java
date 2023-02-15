package com.gdcho.security.service;

import com.gdcho.security.common.Consts;
import com.gdcho.security.common.Status;
import com.gdcho.security.entity.Role;
import com.gdcho.security.entity.Users;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.repository.UsersDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Transactional
@Service
public class UserService {

    @Autowired
    private UsersDao userDao;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    public List<Users> queryAllUsers() {
        return userDao.findAll();
    }

    /**
     * 根据用户ID查询用户
     *
     * @param userId 用户ID
     * @return Users
     */
//    @Nullable
    public Optional<Users> queryUserById(Long userId) {

        return userDao.findById(userId);
    }

    /**
     * 新建用户
     *
     * @return 用户
     */
    public Users createUser(String username,
                            String password,
                            String openId,
                            String sessionKey) {
        boolean existUser = userDao.existsByUsernameIgnoreCase(username);
        if (existUser) {
            throw new SecurityException(Status.USER_IS_EXIST);
        }

        Users registerUser = Users.builder().sex(Consts.SEX_UNKNOWN).username(username)
                                  .password(password)
                                  .nickname(UUID.randomUUID().toString().substring(0, 5)).status(Consts.USER_ENABLE)
                                  .openId(openId).sessionKey(sessionKey)
                                  .lastLoginTime(new Date()).build();

        Role role = roleService.createRoleIfNotExist("COMMON", "普通用户", "sys:user:view");
        HashSet<Role> roleSet = new HashSet<>();
        roleSet.add(role);
        registerUser.setRole(roleSet);

        String enPassword = bCryptPasswordEncoder.encode(password);
        registerUser.setPassword(enPassword);

        return userDao.save(registerUser);
    }

    /**
     * 更新用户，并且会主动更新最后登录日期
     *
     * @param user 用户
     */
    public void updateUser(Users user) {
        // 更新用户最后登录日期信息
        user.setLastLoginTime(new Date());
        userDao.save(user);
    }

    /**
     * 根据openId与unionId查询用户
     *
     * @param openId openId
     * @return 用户
     */
    public Optional<Users> queryUserByOpenId(String openId) {
        return userDao.findByOpenId(openId);
    }

    /**
     * 根据用户名查询用户
     *
     * @param username 用户名
     * @return 用户
     */
    public Optional<Users> queryUserByUsername(String username) {
        return userDao.findByUsername(username);
    }

    /**
     * 删除用户
     *
     * @param userId
     */
    public void deleteUserById(Long userId) {
        userDao.deleteById(userId);
    }

    /**
     * 逻辑删除用户
     */
    public Users deleteUserForLogic(Long userId) {
        Optional<Users> ousers = userDao.findById(userId);
        if (ousers.isEmpty()) {
            throw new SecurityException(Status.USERNAME_NOT_FOUND);
        }
        Users user = ousers.get();
        user.setStatus(Consts.USER_DELETE);
        return userDao.save(user);

    }


}

