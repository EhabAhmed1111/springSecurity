package com.ihab.security;

import com.ihab.security.auth.RegisterRequest;
import com.ihab.security.service.AuthService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.ihab.security.user.Role.ADMIN;
import static com.ihab.security.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

    @Bean
    public CommandLineRunner commandLineRunner (AuthService authService){
        return args -> {
          var admin = RegisterRequest.builder()
                  .firstName("Admin")
                  .lastName("Admin")
                  .email("admin@gmail.com")
                  .password("password")
                  .role(ADMIN)
                  .build();
            System.out.println("ADMIN token: " + authService.register(admin).getToken());

            var manger = RegisterRequest.builder()
                  .firstName("Manger")
                  .lastName("Manger")
                  .email("Manger@gmail.com")
                  .password("password")
                  .role(MANAGER)
                  .build();
            System.out.println("MANGER token: " + authService.register(manger).getToken());
        };
    }
}
