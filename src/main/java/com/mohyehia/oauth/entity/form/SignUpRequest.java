package com.mohyehia.oauth.entity.form;

import lombok.Data;

@Data
public class SignUpRequest {
    private String name;
    private String email;
    private String password;
    private String imageUrl;
}
