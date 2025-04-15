package ru.apronichev.signature_scanner.service;

import ru.apronichev.signature_scanner.dto.SignatureScanResult;
import ru.apronichev.signature_scanner.model.Signature;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.MessageDigest;
import java.util.*;

@Service
@RequiredArgsConstructor
public class FileScanService {

    private final SignatureService signatureService;

    private static final int WINDOW_SIZE = 8;
    private static final int CHUNK_SIZE = 8192;
    private static final long BASE = 256;
    private static final long MOD = 1_000_000_007;

    public List<SignatureScanResult> scanFile(MultipartFile file) throws IOException {
        List<Signature> signatures = signatureService.getAllActualSignatures();
        List<SignatureScanResult> results = new ArrayList<>();

        Map<Long, List<Signature>> rollingHashIndex = new HashMap<>();
        for (Signature sig : signatures) {
            long hash = computeHash(sig.getFirstBytes());
            System.out.println("SIG HASH: " + hash + " | bytes: " + new String(sig.getFirstBytes()));
            rollingHashIndex.computeIfAbsent(hash, k -> new ArrayList<>()).add(sig);
        }

        File tempFile = File.createTempFile("scan-", ".bin");
        file.transferTo(tempFile);

        try (RandomAccessFile raf = new RandomAccessFile(tempFile, "r")) {
            byte[] window = new byte[WINDOW_SIZE];
            long rollingHash = 0;
            long pow = 1;

            int bytesRead;
            long filePointer = 0;
            byte[] buffer = new byte[CHUNK_SIZE];

            while ((bytesRead = raf.read(buffer)) != -1) {
                for (int i = 0; i < bytesRead; i++) {
                    byte b = buffer[i];

                    if (filePointer < WINDOW_SIZE) {
                        rollingHash = (rollingHash * BASE + (b & 0xFF)) % MOD;
                        window[(int) filePointer] = b;
                        filePointer++;

                        if (filePointer == WINDOW_SIZE) {
                            pow = 1;
                            for (int p = 1; p < WINDOW_SIZE; p++) {
                                pow = (pow * BASE) % MOD;
                            }

                            long firstHash = computeHash(window);
                            long currentOffset = 0;

                            if (rollingHashIndex.containsKey(firstHash)) {
                                byte[] candidate = Arrays.copyOf(window, WINDOW_SIZE);
                                for (Signature sig : rollingHashIndex.get(firstHash)) {
                                    if (currentOffset >= sig.getOffsetStart() && currentOffset <= sig.getOffsetEnd()) {
                                        if (Arrays.equals(sig.getFirstBytes(), candidate)) {
                                            raf.seek(WINDOW_SIZE);
                                            byte[] tail = new byte[sig.getRemainderLength()];
                                            raf.read(tail);
                                            String tailHash = hashSHA256(tail);

                                            if (tailHash.equals(sig.getRemainderHash())) {
                                                results.add(SignatureScanResult.builder()
                                                        .signatureId(sig.getId())
                                                        .threatName(sig.getThreatName())
                                                        .offsetFromStart(0)
                                                        .offsetFromEnd(WINDOW_SIZE + sig.getRemainderLength() - 1)
                                                        .matched(true)
                                                        .build());
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        continue;
                    }

                    rollingHash = (rollingHash + MOD - (window[0] & 0xFF) * pow % MOD) % MOD;
                    rollingHash = (rollingHash * BASE + (b & 0xFF)) % MOD;

                    System.arraycopy(window, 1, window, 0, WINDOW_SIZE - 1);
                    window[WINDOW_SIZE - 1] = b;

                    long currentOffset = filePointer - WINDOW_SIZE + 1;
                    System.out.println("HASH@offset " + currentOffset + " = " + rollingHash + " | window = " + new String(window));

                    if (rollingHashIndex.containsKey(rollingHash)) {
                        byte[] candidate = Arrays.copyOf(window, WINDOW_SIZE);
                        for (Signature sig : rollingHashIndex.get(rollingHash)) {
                            if (currentOffset >= sig.getOffsetStart() && currentOffset <= sig.getOffsetEnd()) {
                                if (Arrays.equals(sig.getFirstBytes(), candidate)) {
                                    raf.seek(currentOffset + WINDOW_SIZE);
                                    byte[] tail = new byte[sig.getRemainderLength()];
                                    raf.read(tail);
                                    String tailHash = hashSHA256(tail);

                                    if (tailHash.equals(sig.getRemainderHash())) {
                                        boolean alreadyReported = results.stream().anyMatch(r ->
                                                r.getSignatureId().equals(sig.getId()) &&
                                                        r.getOffsetFromStart() == currentOffset
                                        );
                                        if (!alreadyReported) {
                                            results.add(SignatureScanResult.builder()
                                                    .signatureId(sig.getId())
                                                    .threatName(sig.getThreatName())
                                                    .offsetFromStart((int) currentOffset)
                                                    .offsetFromEnd((int) (currentOffset + WINDOW_SIZE + sig.getRemainderLength() - 1))
                                                    .matched(true)
                                                    .build());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    filePointer++;
                }
            }
        }

        tempFile.delete();
        return results;
    }

    private long computeHash(byte[] data) {
        long hash = 0;
        for (byte b : data) {
            hash = (hash * BASE + (b & 0xFF)) % MOD;
        }
        return hash;
    }

    private String hashSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing tail", e);
        }
    }
}
