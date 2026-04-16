package com.vulnuris.IngestionService.parser;

import com.vulnuris.IngestionService.model.CesEvent;

import java.io.InputStream;
import java.util.stream.Stream;

public interface LogParser {
    Stream<CesEvent> parseStream(InputStream input, String filename);
}
