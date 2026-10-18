begin;

create table public.nf_profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    login text not null unique
        check (login ~ '^[a-z0-9_]{3,24}$'),
    role text not null default 'user'
        check (role in ('user', 'admin')),
    hwid_hash text
        check (hwid_hash is null or hwid_hash ~ '^[a-f0-9]{64}$'),
    epoch bigint not null default 0,
    created_at timestamptz not null default now(),
    last_login timestamptz
);

create table public.nf_sessions (
    session_id uuid primary key,
    user_id uuid not null
        references public.nf_profiles(id) on delete cascade,
    epoch bigint not null,
    created_at timestamptz not null default now()
);

create index nf_sessions_user_idx
    on public.nf_sessions(user_id);

create table public.nf_logs (
    id bigint generated always as identity primary key,
    created_at timestamptz not null default now(),
    actor_id uuid,
    target_id uuid,
    action text not null,
    details jsonb not null default '{}'::jsonb
);

create index nf_logs_created_idx
    on public.nf_logs(created_at desc, id desc);

create table public.nf_rates (
    key text primary key,
    window_start timestamptz not null,
    count integer not null
);

alter table public.nf_profiles enable row level security;
alter table public.nf_sessions enable row level security;
alter table public.nf_logs enable row level security;
alter table public.nf_rates enable row level security;

revoke all on public.nf_profiles
    from public, anon, authenticated;
revoke all on public.nf_sessions
    from public, anon, authenticated;
revoke all on public.nf_logs
    from public, anon, authenticated;
revoke all on public.nf_rates
    from public, anon, authenticated;

grant all on public.nf_profiles to service_role;
grant all on public.nf_sessions to service_role;
grant all on public.nf_logs to service_role;
grant all on public.nf_rates to service_role;

grant usage, select on sequence public.nf_logs_id_seq
    to service_role;

create function public.nf_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_login text;
begin
    v_login := lower(new.raw_user_meta_data ->> 'login');

    if v_login is null or
       v_login !~ '^[a-z0-9_]{3,24}$' then
        raise exception 'LOGIN_INVALID';
    end if;

    insert into public.nf_profiles(id, login)
    values (new.id, v_login);

    insert into public.nf_logs(actor_id, action)
    values (new.id, 'account_registered');

    return new;
end;
$$;

create trigger nf_auth_user_created
after insert on auth.users
for each row execute function public.nf_new_user();

create function public.nf_rate(
    p_key text,
    p_limit integer,
    p_seconds integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_count integer;
begin
    if p_limit < 1 or p_seconds < 1 then
        raise exception 'INVALID_RATE';
    end if;

    insert into public.nf_rates as r(
        key, window_start, count
    )
    values (p_key, now(), 1)
    on conflict (key) do update
    set
        count = case
            when r.window_start <
                now() - make_interval(secs => p_seconds)
            then 1
            else r.count + 1
        end,
        window_start = case
            when r.window_start <
                now() - make_interval(secs => p_seconds)
            then now()
            else r.window_start
        end
    returning count into v_count;

    return v_count <= p_limit;
end;
$$;

create function public.nf_bind(
    p_uid uuid,
    p_sid uuid,
    p_hwid text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    p public.nf_profiles%rowtype;
begin
    if p_hwid !~ '^[a-f0-9]{64}$' then
        raise exception 'HWID_MISMATCH';
    end if;

    select * into p
    from public.nf_profiles
    where id = p_uid
    for update;

    if not found then
        raise exception 'SESSION_REVOKED';
    end if;

    if p.hwid_hash is null then
        update public.nf_profiles
        set hwid_hash = p_hwid
        where id = p_uid;

        insert into public.nf_logs(actor_id, action)
        values (p_uid, 'hwid_bound');
    elsif p.hwid_hash <> p_hwid then
        raise exception 'HWID_MISMATCH';
    end if;

    insert into public.nf_sessions(
        session_id, user_id, epoch
    )
    values (p_sid, p_uid, p.epoch)
    on conflict (session_id) do update
    set epoch = excluded.epoch
    where public.nf_sessions.user_id = excluded.user_id;

    update public.nf_profiles
    set last_login = now()
    where id = p_uid
    returning * into p;

    insert into public.nf_logs(actor_id, action)
    values (p_uid, 'login');

    return to_jsonb(p);
end;
$$;

create function public.nf_check(
    p_uid uuid,
    p_sid uuid,
    p_hwid text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    p public.nf_profiles%rowtype;
begin
    select u.* into p
    from public.nf_profiles u
    join public.nf_sessions s
        on s.user_id = u.id
       and s.epoch = u.epoch
    where u.id = p_uid
      and s.session_id = p_sid
      and u.hwid_hash = p_hwid;

    if not found then
        raise exception 'SESSION_REVOKED';
    end if;

    return to_jsonb(p);
end;
$$;

create function public.nf_reset(
    p_uid uuid,
    p_sid uuid,
    p_hwid text,
    p_target uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_admin jsonb;
begin
    -- Locking the administrator row serializes a simultaneous
    -- reset of their own access with this administrative action.
    perform 1
    from public.nf_profiles
    where id = p_uid
    for update;

    v_admin := public.nf_check(p_uid, p_sid, p_hwid);

    if v_admin ->> 'role' <> 'admin' then
        raise exception 'ADMIN_REQUIRED';
    end if;

    update public.nf_profiles
    set hwid_hash = null,
        epoch = epoch + 1
    where id = p_target;

    if not found then
        raise exception 'USER_NOT_FOUND';
    end if;

    delete from public.nf_sessions
    where user_id = p_target;

    insert into public.nf_logs(
        actor_id, target_id, action
    )
    values (p_uid, p_target, 'admin_hwid_reset');
end;
$$;

revoke all on function public.nf_new_user()
    from public, anon, authenticated;

revoke all on function public.nf_rate(text, integer, integer)
    from public, anon, authenticated;

revoke all on function public.nf_bind(uuid, uuid, text)
    from public, anon, authenticated;

revoke all on function public.nf_check(uuid, uuid, text)
    from public, anon, authenticated;

revoke all on function public.nf_reset(uuid, uuid, text, uuid)
    from public, anon, authenticated;

grant execute on function public.nf_rate(text, integer, integer)
    to service_role;

grant execute on function public.nf_bind(uuid, uuid, text)
    to service_role;

grant execute on function public.nf_check(uuid, uuid, text)
    to service_role;

grant execute on function public.nf_reset(uuid, uuid, text, uuid)
    to service_role;

-- Used only if GitHub serves a binary directly instead of
-- returning a temporary download redirect.
insert into storage.buckets(
    id,
    name,
    public,
    file_size_limit,
    allowed_mime_types
)
values (
    'nf-builds',
    'nf-builds',
    false,
    67108864,
    array['application/octet-stream']
)
on conflict (id) do nothing;

commit;