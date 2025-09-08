Prerequisitos

-Instalar PostgreSQL
-Usuario con permisos

1) Crear Usuario y la base de datos

$env:PGPASSWORD="TU_PASSWORD_DE_SUPERUSUARIO"   # ej. del usuario postgres
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" `
  -h localhost -U postgres -d postgres -f ".\db\ScriptDatabase.sql"

2) Restaurar el dump

$env:PGPASSWORD="TelVot123@"
& "C:\Program Files\PostgreSQL\17\bin\pg_restore.exe" `
  -h localhost -U AdminTelevot -d Televot_APP `
  -j 4 --verbose `
  ".\db\dumps\Televot_APP.dump"
