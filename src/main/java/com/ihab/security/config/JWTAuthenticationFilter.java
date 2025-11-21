package com.ihab.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//this will filter each request once
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    //we can intercept every req and extract data and provide new data for response
    @Override
    protected void doFilterInternal(
            //our req
            @NonNull HttpServletRequest request,
            //our response
            //we can add header to response
            @NonNull HttpServletResponse response,
            //chainOfResponsibility dp (contain the list of other filter that we need to execute)
            //so when we call filterChain.do it will execute the next filter
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //token should path within header
        //Authorization this header  that contain the JWT
        //here it will go to req and look in header and take the token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        //mean حامل للتوكن
        if (authHeader ==null||!authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        //here it will skip this word and go for token
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);
        //i need to check if user already authenticated, so I do not need to do all checking again
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt,userDetails)){
                //this object is needed by spring security in order to update SecurityContextHolder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        //this is null because user doesn't have credential when he was created
                        null,
                        userDetails.getAuthorities()
                );
                //this about details that come from web like ip or session id
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext()  .setAuthentication(authToken);
            }
        }
        //don't forget to call doFilter after each filter executed so it can move to next filter
        filterChain.doFilter(request, response);
    }
}
