-- k-Koçluk · 5. aşama: koçlar için aylık, öğrenci başı kullanım bedeli
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Birden fazla kez çalıştırmak güvenlidir.
-- Önce 01 numaralı dosyanın çalıştırılmış olması gerekir.

-- 1) Genel ayarlar (öğrenci başı aylık bedel burada durur) ----------------------
create table if not exists public.app_settings (
  key    text primary key,
  value  jsonb not null
);

-- Koça özel bedel; boşsa genel bedel uygulanır.
alter table public.profiles add column if not exists student_price numeric(10,2);

-- 2) Koça yazılan aylık bedeller -------------------------------------------------
create table if not exists public.coach_bills (
  id          uuid primary key default gen_random_uuid(),
  coach_id    uuid not null references public.profiles(id) on delete cascade,
  month       text not null check (month ~ '^\d{4}-\d{2}$'),   -- dönem: 2026-10
  students    integer not null check (students >= 0),
  price       numeric(10,2) not null check (price >= 0),
  amount      numeric(12,2) not null check (amount >= 0),
  created_at  timestamptz not null default now(),
  unique (coach_id, month)
);

-- 3) Koçtan alınan ödemeler -------------------------------------------------------
create table if not exists public.coach_payments (
  id          uuid primary key default gen_random_uuid(),
  coach_id    uuid not null references public.profiles(id) on delete cascade,
  amount      numeric(12,2) not null check (amount > 0),
  paid_on     date not null default current_date,
  note        text not null default '',
  created_at  timestamptz not null default now()
);

-- 4) Yetkiler: koç yalnızca kendi bedelini ve ödemesini GÖRÜR; yazma yalnızca yöneticide.
alter table public.app_settings   enable row level security;
alter table public.coach_bills    enable row level security;
alter table public.coach_payments enable row level security;

revoke all on public.app_settings, public.coach_bills, public.coach_payments from anon;
revoke all on public.app_settings, public.coach_bills, public.coach_payments from authenticated;
grant select, insert, update, delete on public.app_settings, public.coach_bills, public.coach_payments to authenticated;

drop policy if exists app_settings_select on public.app_settings;
create policy app_settings_select on public.app_settings for select to authenticated using (true);
drop policy if exists app_settings_write on public.app_settings;
create policy app_settings_write on public.app_settings for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists coach_bills_select on public.coach_bills;
create policy coach_bills_select on public.coach_bills for select to authenticated
  using (coach_id = auth.uid() or public.is_admin());
drop policy if exists coach_bills_write on public.coach_bills;
create policy coach_bills_write on public.coach_bills for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists coach_payments_select on public.coach_payments;
create policy coach_payments_select on public.coach_payments for select to authenticated
  using (coach_id = auth.uid() or public.is_admin());
drop policy if exists coach_payments_write on public.coach_payments;
create policy coach_payments_write on public.coach_payments for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- 5) Yönetici, bir koçun öğrencilerine yazdığı saatlik ve aylık ücretleri değiştirebilir.
--    Koçun diğer kayıtlarına dokunmaz; yalnızca ücret alanlarını günceller.
create or replace function public.admin_set_fees(target uuid, rates jsonb, monthly jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Bu işlemi yalnızca yönetici yapabilir'; end if;
  update public.coach_state
     set data = jsonb_set(jsonb_set(data, '{rates}', coalesce(rates, '{}'::jsonb), true),
                          '{monthly}', coalesce(monthly, '{}'::jsonb), true)
   where coach_id = target;
end $$;
revoke execute on function public.admin_set_fees(uuid, jsonb, jsonb) from public, anon;
grant  execute on function public.admin_set_fees(uuid, jsonb, jsonb) to authenticated;
