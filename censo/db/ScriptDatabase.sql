-- 00_setup_televot.sql
-- Crea/actualiza el rol AdminTelevot y la BD Televot_APP con locales Windows.

-- ===== 1) Cerrar conexiones y eliminar BD si existe (entorno de desarrollo) =====
REVOKE CONNECT ON DATABASE "Televot_APP" FROM PUBLIC;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'Televot_APP' AND pid <> pg_backend_pid();

DROP DATABASE IF EXISTS "Televot_APP";

-- ===== 2) Crear o actualizar el rol administrador =====
DO $$
BEGIN
   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'AdminTelevot') THEN
      RAISE NOTICE 'El rol "AdminTelevot" ya existe, actualizando atributos y contraseña.';
      ALTER ROLE "AdminTelevot"
        WITH LOGIN PASSWORD 'TelVot123@'
        NOSUPERUSER CREATEDB CREATEROLE INHERIT;
   ELSE
      CREATE ROLE "AdminTelevot"
        WITH LOGIN PASSWORD 'TelVot123@'
        NOSUPERUSER CREATEDB CREATEROLE INHERIT;
   END IF;
END$$;

-- ===== 3) Crear la base de datos con el owner y locales indicados =====
CREATE DATABASE "Televot_APP"
    WITH
    OWNER = "AdminTelevot"
    ENCODING = 'UTF8'
    -- Esto solo vale para windows.
    LC_COLLATE = 'Spanish_Spain.1252'
    LC_CTYPE = 'Spanish_Spain.1252'
    LOCALE_PROVIDER = 'libc'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1
    IS_TEMPLATE = False;

-- (Opcional) asegurar privilegios explícitos
GRANT ALL PRIVILEGES ON DATABASE "Televot_APP" TO "AdminTelevot";
