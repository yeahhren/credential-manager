
#ifndef CM_BACKUP_H
#define CM_BACKUP_H

#include "common.h"
#include "util.h"

typedef struct {
    wchar_t *target;
    wchar_t *username;
    wchar_t *password;
    wchar_t *type;
    wchar_t *comment;
    wchar_t *source_file;
} cm_imported_cred;

typedef struct {
    bool     success;
    int      imported_count;
    int      skipped_count;
    int      total_count;
    wchar_t *message;
} cm_import_result;

cm_import_result cm_backup_import(const wchar_t *filePath, const wchar_t *password, bool allowDuplicates);

const cm_vec *cm_imported_store(void);
void          cm_imported_clear(void);

bool cm_backup_export(const wchar_t *outputPath, const wchar_t *format);

#endif
