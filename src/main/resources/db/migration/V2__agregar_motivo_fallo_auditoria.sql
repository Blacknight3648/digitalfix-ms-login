-- Script V2: motivo del fallo de login (mapeado en LoginAudit.motivoFallo)
ALTER TABLE LOG_AUDITORIA_ACCESO ADD MOTIVO_FALLO VARCHAR2(255);
