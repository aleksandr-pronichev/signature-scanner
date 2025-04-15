package ru.apronichev.signature_scanner.repository;

import ru.apronichev.signature_scanner.model.SignatureAudit;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureAuditRepository extends JpaRepository<SignatureAudit, Long> {
}
