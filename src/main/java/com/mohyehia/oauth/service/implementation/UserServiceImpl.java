package com.mohyehia.oauth.service.implementation;

import com.mohyehia.oauth.dao.UserDAO;
import com.mohyehia.oauth.entity.AuthProvider;
import com.mohyehia.oauth.entity.User;
import com.mohyehia.oauth.service.framework.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    private final UserDAO userDAO;

    public UserServiceImpl(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    @Override
    public User findByEmail(String email) {
        return userDAO.findByEmail(email).orElse(null);
    }

    @Override
    public User save(User user) {
        user.setAuthProvider(AuthProvider.LOCAL);
        return userDAO.save(user);
    }
}
