package org.example.springsecurityjwtdemo.task;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.repository.MemoryTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenCleanTask {

    private final MemoryTokenRepository tokenRepository;

    // 매일 자정에 실행
    @Scheduled(cron = "0 0 0 * * ?")
    public void cleanExpiredTokens() {
        tokenRepository.deleteAllExpired();
    }
}
