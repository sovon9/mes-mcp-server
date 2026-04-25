package com.sovon9.mes_mcp_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthStatusController {

    @GetMapping("/health")
    public String health()
    {
        return "working as expected ............";
    }

}
