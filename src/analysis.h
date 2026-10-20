
#ifndef CM_ANALYSIS_H
#define CM_ANALYSIS_H

#include "common.h"

typedef struct {
    int  strength_score;
    bool has_upper, has_lower, has_number, has_special;
    int  password_length;
    int  estimated_crack_minutes;
    const wchar_t *risk_level;
} cm_pw_metrics;

cm_pw_metrics cm_analyze_strength(const wchar_t *password);

#endif
