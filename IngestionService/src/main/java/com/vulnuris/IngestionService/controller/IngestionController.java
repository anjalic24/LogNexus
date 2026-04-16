package com.vulnuris.IngestionService.controller;

import com.vulnuris.IngestionService.context.IngestionContext;
import com.vulnuris.IngestionService.service.IngestionService;
import com.vulnuris.IngestionService.service.LogStreamService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5173"})
@RestController
@RequestMapping("/logs")
@RequiredArgsConstructor
public class IngestionController {

    private final IngestionService ingestionService;
    private final LogStreamService logStreamService;
    private final com.vulnuris.IngestionService.service.BundleControlService bundleControlService;


    @GetMapping("/stream/{bundleId}")
    public SseEmitter stream(@PathVariable String bundleId) {
        System.out.println("🌐 Stream API called for: " + bundleId);
        return logStreamService.createEmitter(bundleId);
    }

    @PostMapping("/cancel/{bundleId}")
    public ResponseEntity<?> cancel(@PathVariable String bundleId) {
        if (bundleId == null || bundleId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "bundleId is required"));
        }
        boolean changed = bundleControlService.cancel(bundleId);
        logStreamService.send(bundleId, "🛑 Cancellation requested by user.");
        return ResponseEntity.ok(Map.of(
                "status", "OK",
                "bundleId", bundleId,
                "alreadyCancelled", !changed
        ));
    }

    @PostMapping("/upload")
    public ResponseEntity<?> upload(
            @RequestParam("files") List<MultipartFile> files) {

        if (files == null || files.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "No files provided"));
        }

        String bundleId = UUID.randomUUID().toString();
        IngestionContext context = new IngestionContext(bundleId);

        List<String> savedPaths = new ArrayList<>();

        try {

            String uploadRoot = System.getProperty("user.dir")
                    + File.separator + "uploads";
            String uploadDir = uploadRoot + File.separator + bundleId + File.separator;

            File dir = new File(uploadDir);
            if (!dir.exists() && !dir.mkdirs()) {
                return ResponseEntity.status(500).body(
                        Map.of("status", "ERROR", "message", "Failed to create upload directory: " + uploadDir)
                );
            }

            for (MultipartFile file : files) {

                String safeName = safeFilename(file.getOriginalFilename());
                if (safeName == null || safeName.isBlank()) {
                    safeName = "upload.log";
                }

                File dest = uniqueFile(uploadDir, safeName);
                String filePath = dest.getAbsolutePath();

                System.out.println("📁 Saving file to: " + filePath);

                file.transferTo(dest);

                savedPaths.add(filePath);
            }

        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    Map.of("status", "ERROR", "message", e.getMessage())
            );
        }


        logStreamService.send(context.getBundleId(), "🆔 BundleID created: " + context.getBundleId());
        ingestionService.processFilesFromDisk(savedPaths, context);

        return ResponseEntity.ok(
                Map.of(
                        "status", "SUCCESS",
                        "bundleId", bundleId
                )
        );
    }

    private static String safeFilename(String original) {
        if (original == null) return null;
        String name = original.replace("\\", "/");
        int idx = name.lastIndexOf('/');
        if (idx >= 0) name = name.substring(idx + 1);
        name = name.replaceAll("[\\r\\n\\t\\u0000]", "");
        name = name.replaceAll("[<>:\"|?*]", "_");
        return name.trim();
    }

    private static File uniqueFile(String dir, String filename) throws IOException {
        File candidate = new File(dir + filename);
        if (!candidate.exists()) return candidate;

        String base = filename;
        String ext = "";
        int dot = filename.lastIndexOf('.');
        if (dot > 0 && dot < filename.length() - 1) {
            base = filename.substring(0, dot);
            ext = filename.substring(dot);
        }

        for (int i = 1; i < 10_000; i++) {
            File f = new File(dir + base + "-" + i + ext);
            if (!f.exists()) return f;
        }
        throw new IOException("Too many files with the same name: " + filename);
    }

}
