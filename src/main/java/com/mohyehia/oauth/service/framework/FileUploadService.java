package com.mohyehia.oauth.service.framework;

import org.springframework.web.multipart.MultipartFile;

public interface FileUploadService {
    boolean uploadImage(MultipartFile multipartFile);
}
