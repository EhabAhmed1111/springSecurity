package com.ihab.security.config;


import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf()
        //here we disable csrf
//                .disable()
        //this will define all request then
        //we will make some authenticated and other we will permit
        //This was the main entry point for configuring authorization rules for HTTP requests
        //Why deprecated: It was replaced with a more flexible and explicit API that separates request matching from authorization rules.
//                .authorizeHttpRequests()
        //this will represent our app pattern
                /*
                What it did before: Used to specify URL patterns that the subsequent authorization rules would apply to.

Why deprecated: The method was too ambiguous - it could mean either "match these requests" or "apply these authorization rules to already matched requests".
                 */
//                .requestMatchers("")
        //this will permit all request that you define in pattern
//                .permitAll()
//                .anyRequest()
//                .authenticated()
                /*
                What it did before: Used to chain different security configurations together.

Why deprecated: The .and() method made configurations harder to read and was considered unnecessary with modern Java DSLs.
                 */
//                .and()
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authenticationProvider(authenticationProvider)
//                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(request ->
                        request
                                .requestMatchers("/api/v1/auth/**")
                                .permitAll()
                                .anyRequest()
                                .authenticated())
                //The .sessionManagement() method in Spring Security configures how HTTP sessions are handled.
                // The key setting here is sessionCreationPolicy(), which determines if and how sessions are created.
/*
    The session parameter is a SessionManagementConfigurer that lets you customize:

        Session creation policy (stateless, always, ifRequired, never)

        Session fixation protection (migrateSession, newSession, none)

        Invalid session handling (redirect, error)

        Maximum sessions allowed (concurrent control)
 */
                .sessionManagement(session ->
                        /*
                        when using stateless
                        You are telling Spring Security:

    Do not create or use HTTP sessions.

    Every request must be authenticated independently (no session persistence).

    No JSESSIONID cookie is generated or used.
                         */
                        /*
                        There are 4 possible SessionCreationPolicy options:
Policy	        Behavior	                                                     Use Case
STATELESS	    No sessions created.Each request must re-authenticate.	         APIs with JWT
ALWAYS	        Always creates a session (even if not needed).	                    Legacy apps requiring sessions
IF_REQUIRED (Default)	Creates a session only when needed (e.g., after login).	Traditional web apps (Spring MVC with Thymeleaf)
NEVER	Doesn’t create sessions, but uses one if it exists.	                        Rarely used
                         */
                        /*
                         Best Practices

    For REST APIs (JWT/OAuth) → Always use STATELESS

        Ensures no server-side state, works with tokens.

    For Traditional Web Apps (Thymeleaf, MVC) → Use IF_REQUIRED (default)

        Sessions help maintain login state.

    For Hybrid Apps (API + Server-side UI) → Separate security configs

        Use different SecurityFilterChain for /api/** (stateless) and /web/** (stateful).


                         */
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //The authenticationProvider (specifically in your JWT setup) is typically an instance of DaoAuthenticationProvider that:
                .authenticationProvider(authenticationProvider)
                /*
                the flow is
                Authentication Flow:

    Requests hit your security filter chain

    Your JWTAuthenticationFilter extracts credentials (usually from Authorization header)

    The AuthenticationManager delegates to your authenticationProvider

    The provider validates the credentials against your UserDetailsService
                 */
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


}
