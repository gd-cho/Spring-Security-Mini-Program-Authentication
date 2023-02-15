package com.gdcho.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.util.Date;

@Data
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public class BaseEntity implements Serializable {
    @Id
    @GeneratedValue(generator = "snowflakeGenerator",
                    strategy = GenerationType.SEQUENCE)
    @GenericGenerator(name = "snowflakeGenerator",
                      strategy = "com.gdcho.security.config.SnowIdGeneratorConfig")
    private Long id;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "create_time",
            nullable = false,
            updatable = false)
    @CreatedDate
    private Date createTime;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "last_update_time",
            nullable = false)
    @LastModifiedDate
    private Date lastUpdateTime;

}
