-- Optional for existing projects: the private Storage fallback for JARs > 64 MiB.
-- The project-level Supabase upload limit must also allow this size.
update storage.buckets set file_size_limit = 268435456 where id = 'nf-builds';
