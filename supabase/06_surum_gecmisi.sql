-- k-Koçluk · 6. aşama: sürüm geçmişi (silinen ya da üzerine yazılan kayıtları geri getirme)
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Birden fazla kez çalıştırmak güvenlidir.
-- Önce 01 ve 03 numaralı dosyaların çalıştırılmış olması gerekir.
--
-- Ne yapar?
--  * Bir koçun kayıtları her değiştiğinde ESKİ hâli coach_state_history tablosuna kopyalanır
--    (en fazla 10 dakikada bir; ama öğrenci, görev ya da deneme sayısı azalıyorsa her seferinde).
--  * Kayıtlar 90 gün saklanır. Koç kalıcı silinirse geçmişi de silinir.
--  * Öğrencilerin gönderdiği kayıtlar koç tarafından işlendikten sonra student_ops_log'da 60 gün tutulur.
--  * Yönetici tüm koçların, koç yalnızca kendi geçmişini görür ve geri yükleyebilir.

-- 1) Tablolar -------------------------------------------------------------------
create table if not exists public.coach_state_history (
  id           bigserial primary key,
  coach_id     uuid not null references public.profiles(id) on delete cascade,
  data         jsonb not null,
  saved_at     timestamptz,                       -- o sürümün kaydedildiği an
  archived_at  timestamptz not null default now(),-- geçmişe alındığı an
  reason       text not null default 'update',    -- update | shrink | delete | restore
  students     integer not null default 0,
  tasks        integer not null default 0,
  exams        integer not null default 0
);
create index if not exists coach_state_history_idx on public.coach_state_history (coach_id, archived_at desc);

create table if not exists public.student_ops_log (
  id          bigint primary key,
  coach_id    uuid not null references public.profiles(id) on delete cascade,
  student_id  text,
  op          jsonb,
  logged_at   timestamptz not null default now()
);

-- 2) Geçmişe alma ---------------------------------------------------------------
create or replace function public.jlen(j jsonb) returns integer
language sql immutable as $$ select case when jsonb_typeof(j) = 'array' then jsonb_array_length(j) else 0 end $$;

create or replace function public.archive_coach_state() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  last_at timestamptz;
  why text := 'update';
begin
  if tg_op = 'DELETE' then
    why := 'delete';
  else
    if new.data is not distinct from old.data then return new; end if;
    if jlen(new.data->'students') < jlen(old.data->'students')
       or jlen(new.data->'tasks') < jlen(old.data->'tasks')
       or jlen(new.data->'exams') < jlen(old.data->'exams') then
      why := 'shrink';
    else
      select max(archived_at) into last_at from coach_state_history where coach_id = old.coach_id;
      if last_at is not null and last_at > now() - interval '10 minutes' then return new; end if;
    end if;
  end if;
  if exists (select 1 from profiles where id = old.coach_id) then
    insert into coach_state_history (coach_id, data, saved_at, reason, students, tasks, exams)
    values (old.coach_id, old.data, old.updated_at, why,
            jlen(old.data->'students'), jlen(old.data->'tasks'), jlen(old.data->'exams'));
  end if;
  delete from coach_state_history where coach_id = old.coach_id and archived_at < now() - interval '90 days';
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $$;

drop trigger if exists coach_state_archive on public.coach_state;
create trigger coach_state_archive
  before update or delete on public.coach_state
  for each row execute function public.archive_coach_state();

create or replace function public.log_student_op() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into student_ops_log (id, coach_id, student_id, op)
  values (old.id, old.coach_id, old.student_id, old.op) on conflict (id) do nothing;
  delete from student_ops_log where logged_at < now() - interval '60 days';
  return old;
end $$;

drop trigger if exists student_ops_archive on public.student_ops;
create trigger student_ops_archive
  before delete on public.student_ops
  for each row execute function public.log_student_op();

-- 3) Geri yükleme ---------------------------------------------------------------
create or replace function public.restore_coach_state(p_id bigint) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare h coach_state_history; t timestamptz;
begin
  select * into h from coach_state_history where id = p_id;
  if not found then raise exception 'Sürüm bulunamadı'; end if;
  if not (public.is_admin() or (h.coach_id = auth.uid() and public.is_approved())) then
    raise exception 'Bu sürümü geri yükleme yetkin yok'; end if;
  -- şu anki hâl, geri yüklemeden önce mutlaka geçmişe alınır
  insert into coach_state_history (coach_id, data, saved_at, reason, students, tasks, exams)
    select coach_id, data, updated_at, 'restore', jlen(data->'students'), jlen(data->'tasks'), jlen(data->'exams')
    from coach_state where coach_id = h.coach_id;
  update coach_state set data = h.data where coach_id = h.coach_id returning updated_at into t;
  if t is null then
    insert into coach_state (coach_id, data) values (h.coach_id, h.data) returning updated_at into t;
  end if;
  return t;
end $$;

-- 4) Yetkiler -------------------------------------------------------------------
alter table public.coach_state_history enable row level security;
alter table public.student_ops_log     enable row level security;
revoke all on public.coach_state_history, public.student_ops_log from anon, authenticated;
grant select on public.coach_state_history, public.student_ops_log to authenticated;

drop policy if exists coach_state_history_select on public.coach_state_history;
create policy coach_state_history_select on public.coach_state_history for select to authenticated
  using ((coach_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists student_ops_log_select on public.student_ops_log;
create policy student_ops_log_select on public.student_ops_log for select to authenticated
  using (public.is_admin());

revoke execute on function public.archive_coach_state() from public, anon, authenticated;
revoke execute on function public.log_student_op()      from public, anon, authenticated;
revoke execute on function public.restore_coach_state(bigint) from public, anon;
grant  execute on function public.restore_coach_state(bigint) to authenticated;
