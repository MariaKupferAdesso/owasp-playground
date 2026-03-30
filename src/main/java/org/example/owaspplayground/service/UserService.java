package org.example.owaspplayground.service;

import lombok.RequiredArgsConstructor;
import org.example.owaspplayground.dto.UserSummary;
import org.example.owaspplayground.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    /** Admin-only: returns all users (password hashes excluded from UserSummary). */
    @Transactional(readOnly = true)
    public List<UserSummary> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserSummary::from)
                .toList();
    }
}
