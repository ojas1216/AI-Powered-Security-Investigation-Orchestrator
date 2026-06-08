-- Runs once at database initialization (mounted into /docker-entrypoint-initdb.d).
-- Creates the NON-superuser application role the API connects as. This is
-- essential: PostgreSQL superusers (and table owners under non-FORCE policies)
-- bypass Row-Level Security, so the app must NOT use the owner/superuser role.
--
-- Trust boundary:
--   aegis      = owner/superuser  -> runs migrations, owns tables (FORCE RLS still applies)
--   aegis_app  = least-privilege  -> what the running API uses; RLS fully enforced

CREATE ROLE aegis_app WITH LOGIN PASSWORD 'aegis_app' NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE aegis TO aegis_app;
GRANT USAGE ON SCHEMA public TO aegis_app;

-- Tables are created later by the migration (as role 'aegis'); ensure the app role
-- automatically receives DML privileges on them.
ALTER DEFAULT PRIVILEGES FOR ROLE aegis IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES FOR ROLE aegis IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO aegis_app;
