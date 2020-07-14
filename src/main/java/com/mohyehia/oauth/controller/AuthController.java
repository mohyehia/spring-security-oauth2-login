package com.mohyehia.oauth.controller;

import com.mohyehia.oauth.entity.User;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Log4j2
public class AuthController {
    private final OAuth2AuthorizedClientService clientService;

    public AuthController(OAuth2AuthorizedClientService clientService) {
        this.clientService = clientService;
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @Secured("ROLE_USER")
    @GetMapping("/oauth2LoginSuccess")
    public String retrieveOauth2LoginInfo(Model model,
                                          @AuthenticationPrincipal OAuth2AuthenticationToken authenticationToken){
        // fetching the client details and user details
        log.info(authenticationToken.getAuthorizedClientRegistrationId()); // client name like facebook, google etc.
        log.info(authenticationToken.getName()); // facebook/google userId

        // 1. Fetching User Info
        OAuth2User oAuth2User = authenticationToken.getPrincipal(); // When you login with OAuth it gives you OAuth2User else UserDetails
        log.info("UserID =>" + oAuth2User.getName()); // returns the userId of facebook something like 12312312313212
        // getAttributes map Contains User details like name, email etc// print the whole map for more details
        log.info("Email =>" + oAuth2User.getAttributes().get("email"));

        //2. Just in case if you want to obtain User's auth token value, refresh token, expiry date etc you can use below snippet
        OAuth2AuthorizedClient authorizedClient = clientService
                .loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(),
                        authenticationToken.getName());
        log.info("Token value =>" + authorizedClient.getAccessToken().getTokenValue());

        //3. Now you have full control on users data.You can either see if user is not present in Database then store it and
        // send welcome email for the first time
        model.addAttribute("name", oAuth2User.getAttribute("name"));
        return "home";
    }

    @Secured("ROLE_USER")
    @GetMapping({"/", "/home"})
    public String retrieveFormLoginInfo(Model model,
                                        @AuthenticationPrincipal Authentication authentication){
        // In form-based login flow you get UserDetails as principal while in Oauth based flow you get Oauth2User
        User user = (User) authentication.getPrincipal();
        log.info("Username =>" + user.getUsername());

        model.addAttribute("name", user.getName());
        return "home";
    }
}
