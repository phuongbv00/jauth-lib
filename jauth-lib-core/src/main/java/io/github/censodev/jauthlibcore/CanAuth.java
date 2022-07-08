package io.github.censodev.jauthlibcore;

import java.util.List;

public interface CanAuth {
    String getSubject();

    String getPrinciple();

    List<String> getAuthorities();
}
