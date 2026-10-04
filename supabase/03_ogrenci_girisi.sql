-- k-Koçluk · 2. aşama (öğrenci): kullanıcı adı ve şifreyle öğrenci girişi
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Önce 01 ve 02 numaralı dosyalar çalışmış olmalı.
-- Birden fazla kez çalıştırmak güvenlidir.

create extension if not exists pgcrypto with schema extensions;

-- 1) Tablolar ---------------------------------------------------------------
-- Öğrenci giriş bilgisi: şifrenin kendisi saklanmaz, yalnızca geri çevrilemeyen özeti saklanır.
create table if not exists public.student_accounts (
  id            uuid primary key default gen_random_uuid(),
  coach_id      uuid not null references public.profiles(id) on delete cascade,
  student_id    text not null,
  username      text not null unique,
  pass_hash     text not null,
  failed        int  not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  unique (coach_id, student_id)
);

-- Öğrencinin açık oturumları.
create table if not exists public.student_sessions (
  token       text primary key
              default replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  account_id  uuid not null references public.student_accounts(id) on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default now() + interval '60 days'
);

-- Öğrencinin gönderdiği kayıtlar. Koçun uygulaması bunları kendi kayıtlarına işler ve buradan siler.
-- Öğrenci koçun kayıtlarına doğrudan yazamaz; yalnızca bu listeye ekleme yapabilir.
create table if not exists public.student_ops (
  id          bigint generated always as identity primary key,
  coach_id    uuid not null references public.profiles(id) on delete cascade,
  student_id  text not null,
  op          jsonb not null,
  created_at  timestamptz not null default now()
);
create index if not exists student_ops_owner on public.student_ops (coach_id, student_id, id);

-- 2) Yetkiler ---------------------------------------------------------------
alter table public.student_accounts enable row level security;
alter table public.student_sessions enable row level security;
alter table public.student_ops      enable row level security;

revoke all on public.student_accounts, public.student_sessions, public.student_ops from anon, authenticated;
-- Koç şifre özetini okuyamaz; yalnızca kullanıcı adını görür.
grant select (id, coach_id, student_id, username, created_at) on public.student_accounts to authenticated;
grant delete on public.student_accounts to authenticated;
grant select, delete on public.student_ops to authenticated;
-- student_sessions tablosuna kimse doğrudan erişemez; yalnızca aşağıdaki işlevler kullanır.

drop policy if exists student_accounts_select on public.student_accounts;
create policy student_accounts_select on public.student_accounts for select to authenticated
  using ((coach_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists student_accounts_delete on public.student_accounts;
create policy student_accounts_delete on public.student_accounts for delete to authenticated
  using (coach_id = auth.uid() and public.is_approved());

drop policy if exists student_ops_select on public.student_ops;
create policy student_ops_select on public.student_ops for select to authenticated
  using ((coach_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists student_ops_delete on public.student_ops;
create policy student_ops_delete on public.student_ops for delete to authenticated
  using (coach_id = auth.uid() and public.is_approved());

-- 3) İç yardımcılar ---------------------------------------------------------
-- Koçun hesabı kullanıma açık mı (onaylı, dondurulmamış, süresi geçmemiş)?
create or replace function public.coach_active(p_coach uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = p_coach and approved
                   and (role = 'admin' or (not frozen and (paid_until is null or paid_until >= current_date))));
$$;

-- Bir öğrenciye ait kayıtları koçun verisinden ayıklar. p_role: 'parent' ya da 'student'.
create or replace function public.member_data(p_coach uuid, p_sid text, p_role text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  d    jsonb;
  st   jsonb;
  cids jsonb;
  exs  jsonb;
begin
  select data into d from public.coach_state where coach_id = p_coach;
  if d is null then return null; end if;
  select s into st from jsonb_array_elements(coalesce(d->'students', '[]'::jsonb)) s
   where s->>'id' = p_sid limit 1;
  if st is null then return null; end if;

  cids := case when jsonb_typeof(st->'curIds') = 'array' then st->'curIds'
               else jsonb_build_array(st->'curId') end;

  if p_role = 'student' then
    -- Çözülmemiş denemelerde cevap anahtarı ve konu eşlemesi gönderilmez.
    -- Öğrenci denemeyi bitirdiğini gönderdiyse anahtar açılır ki sonucunu görebilsin.
    select coalesce(jsonb_agg(
             case when e->>'done' = 'true'
                    or exists (select 1 from public.student_ops o
                                where o.coach_id = p_coach and o.student_id = p_sid
                                  and o.op->>'t' = 'exam.save' and o.op->>'id' = e->>'id' and o.op->>'done' = 'true')
                  then e
                  else jsonb_set(e, '{sections}', coalesce((select jsonb_agg((sec - 'key') - 'topics' order by so)
                         from jsonb_array_elements(coalesce(e->'sections', '[]'::jsonb)) with ordinality y(sec, so)), '[]'::jsonb))
             end order by o), '[]'::jsonb)
      into exs
      from jsonb_array_elements(coalesce(d->'exams', '[]'::jsonb)) with ordinality x(e, o)
     where e->>'sid' = p_sid;
    st := (st - 'notes') - 'reportNote';
  else
    select coalesce(jsonb_agg(e order by o), '[]'::jsonb) into exs
      from jsonb_array_elements(coalesce(d->'exams', '[]'::jsonb)) with ordinality x(e, o)
     where e->>'sid' = p_sid and e->>'done' = 'true';
    st := st - 'notes';
  end if;

  return jsonb_build_object(
    'v', 1,
    'active', p_sid,
    'students',  jsonb_build_array(st),
    'curricula', coalesce((select jsonb_agg(c order by o) from jsonb_array_elements(coalesce(d->'curricula', '[]'::jsonb)) with ordinality x(c, o)
                            where cids ? (c->>'id')), '[]'::jsonb),
    'tasks',     coalesce((select jsonb_agg(t order by o) from jsonb_array_elements(coalesce(d->'tasks', '[]'::jsonb)) with ordinality x(t, o)
                            where t->>'sid' = p_sid), '[]'::jsonb),
    'questions', coalesce((select jsonb_agg(q order by o) from jsonb_array_elements(coalesce(d->'questions', '[]'::jsonb)) with ordinality x(q, o)
                            where q->>'sid' = p_sid), '[]'::jsonb),
    'exams',     exs,
    'progress',  jsonb_build_object(p_sid, coalesce(d->'progress'->p_sid, '{}'::jsonb)),
    'plans',     jsonb_build_object(p_sid, coalesce(d->'plans'->p_sid, '{"weeks":{}}'::jsonb)),
    'books',     case when p_role = 'student' then coalesce(d->'books', '[]'::jsonb) else '[]'::jsonb end
  );
end $$;

-- Koçun henüz işlemediği öğrenci kayıtları.
create or replace function public.member_ops(p_coach uuid, p_sid text) returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(op order by id), '[]'::jsonb)
    from public.student_ops where coach_id = p_coach and student_id = p_sid;
$$;

-- 4) Koçun kullandığı işlev: öğrenciye giriş bilgisi verir ya da şifresini yeniler -----
create or replace function public.coach_set_student_login(p_student_id text, p_username text, p_password text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  u   text := lower(btrim(coalesce(p_username, '')));
  acc uuid;
begin
  if auth.uid() is null or not public.is_approved() then
    return jsonb_build_object('error', 'denied'); end if;
  if coalesce(p_student_id, '') = '' then return jsonb_build_object('error', 'student'); end if;
  if u !~ '^[a-z0-9._-]{3,30}$' then return jsonb_build_object('error', 'username'); end if;
  if length(coalesce(p_password, '')) < 6 or length(p_password) > 72 then
    return jsonb_build_object('error', 'password'); end if;
  begin
    insert into public.student_accounts (coach_id, student_id, username, pass_hash)
    values (auth.uid(), p_student_id, u, extensions.crypt(p_password, extensions.gen_salt('bf')))
    on conflict (coach_id, student_id) do update
      set username = excluded.username, pass_hash = excluded.pass_hash, failed = 0, locked_until = null
    returning id into acc;
  exception when unique_violation then
    return jsonb_build_object('error', 'taken');
  end;
  delete from public.student_sessions where account_id = acc;  -- şifre değişince açık oturumlar kapanır
  return jsonb_build_object('ok', true, 'username', u);
end $$;

-- 5) Öğrencinin kullandığı işlevler -----------------------------------------
create or replace function public.student_login(p_username text, p_password text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  a   public.student_accounts%rowtype;
  tok text;
begin
  select * into a from public.student_accounts where username = lower(btrim(coalesce(p_username, '')));
  if not found then return jsonb_build_object('error', 'invalid'); end if;
  if a.locked_until is not null and a.locked_until > now() then
    return jsonb_build_object('error', 'locked'); end if;
  if a.pass_hash <> extensions.crypt(coalesce(p_password, ''), a.pass_hash) then
    update public.student_accounts
       set failed = case when failed + 1 >= 8 then 0 else failed + 1 end,
           locked_until = case when failed + 1 >= 8 then now() + interval '10 minutes' else locked_until end
     where id = a.id;
    return jsonb_build_object('error', 'invalid');
  end if;
  if not public.coach_active(a.coach_id) then return jsonb_build_object('error', 'inactive'); end if;
  update public.student_accounts set failed = 0, locked_until = null where id = a.id;
  delete from public.student_sessions where expires_at < now();
  insert into public.student_sessions (account_id) values (a.id) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.student_view(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  a public.student_accounts%rowtype;
  d jsonb;
begin
  select acc.* into a from public.student_sessions s join public.student_accounts acc on acc.id = s.account_id
   where s.token = p_token and s.expires_at > now();
  if not found then return jsonb_build_object('error', 'session'); end if;
  if not public.coach_active(a.coach_id) then return jsonb_build_object('error', 'inactive'); end if;
  d := public.member_data(a.coach_id, a.student_id, 'student');
  if d is null then return jsonb_build_object('error', 'notfound'); end if;
  return jsonb_build_object(
    'ok', true,
    'coach', coalesce((select nullif(full_name, '') from public.profiles where id = a.coach_id), 'Koç'),
    'username', a.username,
    'data', d,
    'ops', public.member_ops(a.coach_id, a.student_id));
end $$;

-- Öğrenci yalnızca belirli türde kayıt gönderebilir; hiçbiri silme ya da koçun görevini değiştirme içermez.
create or replace function public.student_push(p_token text, p_ops jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  a public.student_accounts%rowtype;
  o jsonb;
  n int := 0;
begin
  select acc.* into a from public.student_sessions s join public.student_accounts acc on acc.id = s.account_id
   where s.token = p_token and s.expires_at > now();
  if not found then return jsonb_build_object('error', 'session'); end if;
  if not public.coach_active(a.coach_id) then return jsonb_build_object('error', 'inactive'); end if;
  if jsonb_typeof(p_ops) <> 'array' or jsonb_array_length(p_ops) > 100 then
    return jsonb_build_object('error', 'invalid'); end if;
  if (select count(*) from public.student_ops where coach_id = a.coach_id and student_id = a.student_id) > 5000 then
    return jsonb_build_object('error', 'full'); end if;
  for o in select * from jsonb_array_elements(p_ops) loop
    if jsonb_typeof(o) <> 'object'
       or coalesce(o->>'t', '') not in ('task.done', 'task.extra', 'mx.add', 'mx.len', 'mx.set', 'exam.save')
       or pg_column_size(o) > 200000 then
      continue;
    end if;
    if o->>'t' = 'exam.save' then   -- aynı denemenin önceki ara kayıtlarını tutma
      delete from public.student_ops
       where coach_id = a.coach_id and student_id = a.student_id
         and op->>'t' = 'exam.save' and op->>'id' = o->>'id';
    end if;
    insert into public.student_ops (coach_id, student_id, op) values (a.coach_id, a.student_id, o);
    n := n + 1;
  end loop;
  return jsonb_build_object('ok', true, 'n', n);
end $$;

create or replace function public.student_logout(p_token text) returns jsonb
language sql security definer set search_path = public as $$
  with x as (delete from public.student_sessions where token = p_token returning 1)
  select jsonb_build_object('ok', true);
$$;

-- 6) Veli görünümü: öğrencinin koça henüz işlenmemiş kayıtlarını da içersin -----
create or replace function public.parent_view(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  l public.parent_links%rowtype;
  d jsonb;
begin
  if p_token is null or length(p_token) < 32 then
    return jsonb_build_object('error', 'notfound'); end if;
  select * into l from public.parent_links where token = p_token;
  if not found then return jsonb_build_object('error', 'notfound'); end if;
  if not public.coach_active(l.coach_id) then return jsonb_build_object('error', 'inactive'); end if;
  d := public.member_data(l.coach_id, l.student_id, 'parent');
  if d is null then return jsonb_build_object('error', 'notfound'); end if;
  return jsonb_build_object(
    'ok', true,
    'coach', coalesce((select nullif(full_name, '') from public.profiles where id = l.coach_id), 'Koç'),
    'data', d,
    'ops', public.member_ops(l.coach_id, l.student_id));
end $$;

-- 7) İşlev yetkileri ----------------------------------------------------------
revoke execute on function public.coach_active(uuid)               from public, anon, authenticated;
revoke execute on function public.member_data(uuid, text, text)    from public, anon, authenticated;
revoke execute on function public.member_ops(uuid, text)           from public, anon, authenticated;
revoke execute on function public.coach_set_student_login(text, text, text) from public, anon;
grant  execute on function public.coach_set_student_login(text, text, text) to authenticated;
revoke execute on function public.student_login(text, text)  from public;
revoke execute on function public.student_view(text)         from public;
revoke execute on function public.student_push(text, jsonb)  from public;
revoke execute on function public.student_logout(text)       from public;
revoke execute on function public.parent_view(text)          from public;
grant  execute on function public.student_login(text, text)  to anon, authenticated;
grant  execute on function public.student_view(text)         to anon, authenticated;
grant  execute on function public.student_push(text, jsonb)  to anon, authenticated;
grant  execute on function public.student_logout(text)       to anon, authenticated;
grant  execute on function public.parent_view(text)          to anon, authenticated;

-- Kontrol: 0 (ya da var olan öğrenci girişi sayısı) görmelisin.
select count(*) as ogrenci_girisi_sayisi from public.student_accounts;
