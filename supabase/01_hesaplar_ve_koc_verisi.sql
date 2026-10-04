-- k-Koçluk · 1. aşama: hesaplar, koç onayı, üyelik (dondurma / silme) ve her koçun kendi verisi
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Birden fazla kez çalıştırmak güvenlidir.

-- 1) Tablolar ---------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text,
  full_name   text not null default '',
  role        text not null default 'coach' check (role in ('admin','coach')),
  approved    boolean not null default false,   -- yalnızca yönetici değiştirebilir
  created_at  timestamptz not null default now()
);

create table if not exists public.coach_state (
  coach_id    uuid primary key references public.profiles(id) on delete cascade,
  data        jsonb not null default '{}'::jsonb,   -- koçun paneldeki tüm kayıtları
  updated_at  timestamptz not null default now()
);

-- Üyelik alanları (dosyanın önceki sürümünü çalıştırdıysan da güvenle eklenir)
alter table public.profiles add column if not exists frozen     boolean not null default false; -- dondurulmuş: kayıtlar durur, erişim kapalı
alter table public.profiles add column if not exists paid_until date;                            -- üyelik bitiş tarihi; boşsa süresiz
alter table public.profiles add column if not exists admin_note text not null default '';        -- yöneticinin kendi notu

-- 2) Yardımcı işlevler ------------------------------------------------------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and approved);
$$;

-- Erişim hakkı: onaylı, dondurulmamış ve üyelik süresi geçmemiş. Yönetici her zaman erişir.
create or replace function public.is_approved() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and approved
                   and (role = 'admin'
                        or (not frozen and (paid_until is null or paid_until >= current_date))));
$$;

-- Yönetici bir koçu ve tüm kayıtlarını kalıcı olarak siler. Geri alınamaz.
create or replace function public.admin_delete_coach(target uuid) returns text
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Bu işlemi yalnızca yönetici yapabilir'; end if;
  if target = auth.uid() then raise exception 'Kendi hesabını silemezsin'; end if;
  if exists (select 1 from public.profiles where id = target and role = 'admin') then
    raise exception 'Yönetici hesabı bu yolla silinemez'; end if;
  delete from public.coach_state where coach_id = target;
  delete from public.profiles    where id = target;
  begin
    delete from auth.users where id = target;
  exception when others then
    return 'Kayıtlar silindi; giriş hesabını Authentication > Users sayfasından ayrıca sil';
  end;
  return 'Koç ve tüm kayıtları silindi';
end $$;

-- Yeni kaydolan herkes "onay bekleyen koç" olarak açılır.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', ''))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Kayıt her değiştiğinde saatini güncelle.
create or replace function public.touch_updated_at() returns trigger
language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists coach_state_touch on public.coach_state;
create trigger coach_state_touch
  before update on public.coach_state
  for each row execute function public.touch_updated_at();

-- 3) Yetkiler ---------------------------------------------------------------
alter table public.profiles    enable row level security;
alter table public.coach_state enable row level security;

revoke all on public.profiles, public.coach_state from anon;
revoke all on public.profiles, public.coach_state from authenticated;
grant select, update          on public.profiles    to authenticated;
grant select, insert, update  on public.coach_state to authenticated;

revoke execute on function public.handle_new_user()  from public, anon, authenticated;
revoke execute on function public.touch_updated_at() from public, anon, authenticated;
revoke execute on function public.is_admin()    from public, anon;
revoke execute on function public.is_approved() from public, anon;
grant  execute on function public.is_admin()    to authenticated;
grant  execute on function public.is_approved() to authenticated;
revoke execute on function public.admin_delete_coach(uuid) from public, anon;
grant  execute on function public.admin_delete_coach(uuid) to authenticated;  -- içeride yönetici kontrolü var

-- Profil: herkes yalnızca kendi satırını görür; yönetici hepsini görür.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());

-- Profil: onay, rol, dondurma ve üyelik tarihini yalnızca yönetici değiştirebilir.
drop policy if exists profiles_admin_update on public.profiles;
create policy profiles_admin_update on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- Koç verisi: erişim hakkı olan koç yalnızca kendi kaydını okur ve yazar; yönetici hepsini okur.
-- Dondurulan ya da süresi geçen koç kendi kaydını da göremez; kayıt silinmez, yerinde durur.
drop policy if exists coach_state_select on public.coach_state;
create policy coach_state_select on public.coach_state for select to authenticated
  using ((coach_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists coach_state_insert on public.coach_state;
create policy coach_state_insert on public.coach_state for insert to authenticated
  with check (coach_id = auth.uid() and public.is_approved());

drop policy if exists coach_state_update on public.coach_state;
create policy coach_state_update on public.coach_state for update to authenticated
  using (coach_id = auth.uid() and public.is_approved())
  with check (coach_id = auth.uid() and public.is_approved());

-- 4) Var olan kullanıcılar ve yönetici ---------------------------------------
-- Bu dosyadan önce açılmış kullanıcıların profilini oluştur.
insert into public.profiles (id, email)
select id, email from auth.users
on conflict (id) do nothing;

-- Yönetici hesabı: aşağıdaki e-posta senin giriş e-postan olmalı.
update public.profiles
set role = 'admin', approved = true
where email = 'YONETICI_EPOSTASI';

-- Kontrol: en az bir satır ve role = admin, approved = true görmelisin.
select email, role, approved, frozen, paid_until from public.profiles order by created_at;
