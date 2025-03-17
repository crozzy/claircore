-- additional_data
CREATE EXTENSION IF NOT EXISTS lo;
CREATE TABLE IF NOT EXISTS additional_data (
    namespace TEXT,
    lookup_key TEXT,
    data lo
);
CREATE UNIQUE INDEX IF NOT EXISTS additional_data_unique_idx ON additional_data (namespace, lookup_key);

-- Trigger needed to clean up orphaned objects
-- see: https://www.postgresql.org/docs/current/lo.html#LO-HOW-TO-USE
-- Can't IF NOT EXISTS a trigger, so have to manually delete and recreate.
DO $$
BEGIN
    -- Drop the trigger if it exists
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 't_data') THEN
        DROP TRIGGER t_data ON additional_data;
    END IF;

    -- Create the trigger
    CREATE TRIGGER t_data BEFORE UPDATE OR DELETE ON additional_data
    FOR EACH ROW EXECUTE FUNCTION lo_manage(data);
END;
$$ LANGUAGE plpgsql;
