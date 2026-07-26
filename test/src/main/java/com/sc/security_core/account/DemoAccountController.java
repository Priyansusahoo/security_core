package com.sc.security_core.account;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/api/demo-account/")
@Deprecated
public class DemoAccountController {

    @GetMapping("/my-balance")
    public ResponseEntity<Map<String, Object>> getMyBalance() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assert authentication != null;
        String currentEmail = authentication.getName();

        return ResponseEntity.ok(Map.of(
                "accountOwner", currentEmail,
                "balance", "$1,500.00",
                "status", "ACTIVE"
        ));
    }

    @GetMapping("/admin/all-accounts")
    public ResponseEntity<Map<String, Object>> getAllAccounts() {
        return ResponseEntity.ok(Map.of(
                "totalAccounts", 142,
                "totalVaultFunds", "$2,450,000.00",
                "message", "Welcome, Administrator! You have access to restricted system data."
        ));
    }
}
