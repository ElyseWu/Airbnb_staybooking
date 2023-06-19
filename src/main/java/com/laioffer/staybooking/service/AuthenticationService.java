package com.laioffer.staybooking.service;

import org.springframework.stereotype.Service;
import com.laioffer.staybooking.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import com.laioffer.staybooking.exception.UserNotExistException;
import com.laioffer.staybooking.model.Token;
import com.laioffer.staybooking.model.User;
import com.laioffer.staybooking.model.UserRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthenticationService(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    public Token authenticate(User user, UserRole role) throws UserNotExistException {
        Authentication auth = null;
        try {
            auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        } catch (AuthenticationException exception) {
            throw new UserNotExistException("User Doesn't Exist");
        }

        //上一步try catch后，信息会存在auth中，auth.isAuthenticated()是储存了用户是否是用户名密码正确的
        //用户不存在||密码错误||权限不对
        if (auth == null || !auth.isAuthenticated() || !auth.getAuthorities().contains(new SimpleGrantedAuthority(role.name()))) {
            throw new UserNotExistException("User has no permission to access");
        }
        return new Token(jwtUtil.generateToken(user.getUsername()));
    }

}
