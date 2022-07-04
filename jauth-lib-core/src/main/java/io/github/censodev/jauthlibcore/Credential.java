package io.github.censodev.jauthlibcore;

import java.util.List;

public interface Credential {
    String getSubject();

    String getPrinciple();

    List<String> getAuthorities();
}
