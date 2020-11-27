package com.mohyehia.oauth.controller;

import com.mohyehia.oauth.entity.User;
import com.mohyehia.oauth.entity.form.SignUpRequest;
import com.mohyehia.oauth.service.framework.UserService;
import com.mohyehia.oauth.utils.AppConstant;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

@Controller
@Log4j2
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${spring.servlet.multipart.location}")
    private String path;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String viewLoginPage(){
        return "login";
    }

    @GetMapping("/signup")
    public String viewSignupPage(Model model){
        model.addAttribute("signUpRequest", new SignUpRequest());
        return "signup";
    }

    @PostMapping("/signup")
    public String saveNewUser(@ModelAttribute("signUpRequest") SignUpRequest signUpRequest,
                              Model model,
                              @RequestParam("image") MultipartFile file,
                              RedirectAttributes attributes) throws Exception {
        log.info("Submitted data =>" + signUpRequest);
        log.info("Submitted image name =>" + file.getOriginalFilename());
        if(userService.findByEmail(signUpRequest.getEmail()) != null){
            model.addAttribute("signUpRequest", signUpRequest);
            model.addAttribute("error", "Email Address already exists!");
            return "signup";
        }
        String profileImage = "";
        // check if image is valid
        if(valid(file)){
            // upload image and get the image url to set it as the user profileImage
            log.info("Path =>" + path);
            String fileName = UUID.randomUUID().toString();
            String fileExtension = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf('.') + 1);
            log.info("FileName =>" + fileName + ", fileExtension =>" + fileExtension);
            fileName += "." + fileExtension;
            profileImage = path + fileName;
            log.info("ProfileImage =>" + profileImage);
            Files.copy(file.getInputStream(), Paths.get(path + fileName));
        }
        // save user to database & redirect to login for now
        User user = new User();
        user.setName(signUpRequest.getName());
        user.setEmail(signUpRequest.getEmail());
        user.setAuthProvider(AppConstant.LOCAL_PROVIDER);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setProfileImage(profileImage);
        User savedUser = userService.save(user);
        if(savedUser == null){
            model.addAttribute("signUpRequest", signUpRequest);
            model.addAttribute("error", "An error occurred while performing your request, please try again!");
            return "signup";
        }
        log.info("new user saved successfully!");
        attributes.addFlashAttribute("success", "Your account created successfully, you can now login with your credentials!");
        return "redirect:/login";
    }

    private boolean valid(MultipartFile file) {
        if(file.isEmpty()){
            return false;
        }
        if(file.getContentType() != null){
            if(!file.getContentType().equalsIgnoreCase("image/png")
                    && !file.getContentType().equalsIgnoreCase("image/jpeg")){
                return false;
            }
        }
        return file.getSize() <= 1024 * 1024;
    }
}
