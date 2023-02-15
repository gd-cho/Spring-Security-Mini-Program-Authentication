package com.gdcho.security.service;

import com.gdcho.security.common.Consts;
import com.gdcho.security.entity.Role;
import com.gdcho.security.repository.RoleDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class RoleService {
    @Autowired
    private RoleDao roleDao;

    /**
     * 查询所有角色
     */
    public List<Role> queryAllRole() {
        return roleDao.findAll();
    }

    /**
     * 通过用户id查询角色
     */
    public Set<Role> queryRoleByUserId(Long userId) {
        return roleDao.findByUsers_Id(userId);
    }


    /**
     * 通过角色名查询角色
     *
     * @param name 角色名称
     * @return 角色
     */
    public Optional<Role> queryRoleByName(String name) {
        return roleDao.findByNameIgnoreCase(name);
    }

    public boolean existsByNameIgnoreCase(String name) {
        return roleDao.existsByNameIgnoreCase(name);
    }

    public Role createRoleIfNotExist(String name,
                                     String desc,
                                     String perms) {
        Optional<Role> orole = queryRoleByName(name);
        if (orole.isPresent()) {
            return orole.get();
        }
        Role role = Role.builder().name(name).roleDesc(desc).status(Consts.USER_ENABLE).url("/")
                        .perms(perms).type(Consts.BTN).build();
        return roleDao.save(role);
    }


    /**
     * 查询用户id拥有的权限
     */
    public Set<String> queryRolePermsByUserId(Long userId) {
        Set<Role> roleSet = roleDao.findByUsers_Id(userId);
        Set<String> permSet = new HashSet<>();

        for (Role role : roleSet) {
            List<String> allPerms = Arrays.asList(role.getPerms().trim().split(","));
            permSet.addAll(allPerms);
        }
        return permSet;
    }

    /**
     * 添加角色
     */
    public void createRole(Role role) {
        boolean isNameExist = roleDao.existsByNameIgnoreCase(role.getName());

        if (isNameExist) {
            throw new RuntimeException(role.getName() + "角色已存在！");
        }
        roleDao.save(role);
    }

    /**
     * 修改角色信息
     */
    public void updateRole(Role role) {
        roleDao.save(role);
    }

}
