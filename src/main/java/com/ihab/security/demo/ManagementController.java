package com.ihab.security.demo;


import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRoles('ADMIN', 'MANAGER')")
public class ManagementController {

    @GetMapping
    @PreAuthorize("hasAnyAuthorities('admin:read', 'manger:read')")
    public String get() {
        return "GET:: management controller";
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthorities('admin:create', 'manger:create')")
    public String post() {
        return "POST:: management controller";
    }

    @PutMapping
    @PreAuthorize("hasAnyAuthorities('admin:update', 'manger:update')")
    public String put() {
        return "PUT:: management controller";
    }

    @DeleteMapping
    @PreAuthorize("hasAnyAuthorities('admin:delete', 'manger:delete')")
    public String delete() {
        return "DELETE:: management controller";
    }
}
