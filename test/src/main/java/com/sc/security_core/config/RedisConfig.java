package com.sc.security_core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis infrastructure configuration.
 * <p>
 * Exposes a typed {@link RedisTemplate} for persisting domain records such as
 * {@code OtpSession} and {@code MfaChallenge} with String keys and serialized payloads.
 * </p>
 */
@Configuration
public class RedisConfig {

    /**
     * Configures a {@link RedisTemplate} with UTF-8 String keys and JDK serialized values.
     * Both {@code OtpSession} and {@code MfaChallenge} implement {@link java.io.Serializable}.
     *
     * @param connectionFactory the active Redis connection factory
     * @return configured {@link RedisTemplate} instance
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        JdkSerializationRedisSerializer valueSerializer = new JdkSerializationRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(valueSerializer);
        template.setHashValueSerializer(valueSerializer);
        template.afterPropertiesSet();
        return template;
    }
}