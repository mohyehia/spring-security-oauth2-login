package com.mohyehia.oauth.service.framework;

import com.mohyehia.oauth.entity.User;

public interface UserService {
    User findByEmail(String email);
    User save(User user);
}
