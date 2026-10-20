#include "analysis.h"
#include <math.h>
#include <wchar.h>
#include <string.h>

cm_pw_metrics cm_analyze_strength(const wchar_t *password)
{
    cm_pw_metrics m = {0};
    m.password_length = password ? (int)wcslen(password) : 0;
    if (!password || m.password_length == 0) {
        m.risk_level = L"Critical";
        m.strength_score = 0;
        return m;
    }

    static const wchar_t *specials = L"!@#$%^&*()_+-=[]{};':\"\\|,.<>/?";
    for (const wchar_t *p = password; *p; p++) {
        if (*p >= L'A' && *p <= L'Z') m.has_upper = true;
        else if (*p >= L'a' && *p <= L'z') m.has_lower = true;
        else if (*p >= L'0' && *p <= L'9') m.has_number = true;
        else if (wcschr(specials, *p)) m.has_special = true;
    }

    int score = 0;
    if (m.has_upper) score += 20;
    if (m.has_lower) score += 20;
    if (m.has_number) score += 20;
    if (m.has_special) score += 20;
    if (m.password_length >= 12) score += 20;
    else if (m.password_length >= 8) score += 10;
    if (score > 100) score = 100;
    m.strength_score = score;

    double entropy = 0;
    if (m.has_lower) entropy += 26;
    if (m.has_upper) entropy += 26;
    if (m.has_number) entropy += 10;
    if (m.has_special) entropy += 32;
    double permutations = pow(entropy, m.password_length);
    double guesses_per_sec = 1e9;
    double minutes = permutations / (guesses_per_sec * 60.0);
    m.estimated_crack_minutes = (minutes > 2147483647.0) ? 2147483647 : (int)minutes;

    if (m.strength_score >= 80) m.risk_level = L"Low";
    else if (m.strength_score >= 60) m.risk_level = L"Medium";
    else if (m.strength_score >= 40) m.risk_level = L"High";
    else m.risk_level = L"Critical";
    return m;
}
