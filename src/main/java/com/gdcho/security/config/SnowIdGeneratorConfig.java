package com.gdcho.security.config;

import cn.hutool.core.lang.Snowflake;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.IdentifierGenerator;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 自定义JPA的ID生成算法
 */
public class SnowIdGeneratorConfig implements IdentifierGenerator {

    @Autowired
    Snowflake snowflake;

    @Override
    public Object generate(SharedSessionContractImplementor session,
                           Object object) throws HibernateException {

        return snowflake.nextId();
    }
}
