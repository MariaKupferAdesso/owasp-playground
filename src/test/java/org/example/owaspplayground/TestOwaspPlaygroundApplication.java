package org.example.owaspplayground;

import org.springframework.boot.SpringApplication;

public class TestOwaspPlaygroundApplication {

    public static void main(String[] args) {
        SpringApplication.from(OwaspPlaygroundApplication::main).with(TestcontainersConfiguration.class).run(args);
    }

}
