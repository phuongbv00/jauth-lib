package io.github.censodev.jauthlibcore;

import java.util.List;

public interface CanAuth {
    Object principle();

    List<String> authorities();
}
