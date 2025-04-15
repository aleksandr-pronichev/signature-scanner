package ru.apronichev.signature_scanner.repository;

import ru.apronichev.signature_scanner.model.SignatureHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureHistoryRepository extends JpaRepository<SignatureHistory, Long> {
}
