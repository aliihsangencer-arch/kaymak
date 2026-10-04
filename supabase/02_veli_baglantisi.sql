-- k-Koçluk · 2. aşama (veli): öğrenciye özel, şifresiz veli bağlantısı
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Önce 01 numaralı dosya çalışmış olmalı.
-- Birden fazla kez çalıştırmak güvenlidir.

-- 1) Bağlantı tablosu: her öğrenci için en fazla bir geçerli bağlantı
create table if not exists public.parent_links (
  token       text primary key
              default replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  coach_id    uuid not null references public.profiles(id) on delete cascade,
  student_id  text not null,
  created_at  timestamptz not null default now(),
  unique (coach_id, student_id)
);

alter table public.parent_links enable row level security;
revoke all on public.parent_links from anon, authenticated;
grant select, insert, delete on public.parent_links to authenticated;

-- Koç yalnızca kendi öğrencilerinin bağlantılarını görür, oluşturur ve iptal eder; yönetici hepsini görür.
drop policy if exists parent_links_select on public.parent_links;
create policy parent_links_select on public.parent_links for select to authenticated
  using ((coach_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists parent_links_insert on public.parent_links;
create policy parent_links_insert on public.parent_links for insert to authenticated
  with check (coach_id = auth.uid() and public.is_approved());

drop policy if exists parent_links_delete on public.parent_links;
create policy parent_links_delete on public.parent_links for delete to authenticated
  using (coach_id = auth.uid() and public.is_approved());

-- 2) Veli görünümü: bağlantıdaki öğrencinin kayıtlarını, yalnızca o öğrenciye ait olanları döndürür.
--    Koç notları, diğer öğrenciler ve henüz çözülmemiş denemeler (cevap anahtarları) dışarıda kalır.
--    Koçun hesabı onaysız, dondurulmuş ya da süresi dolmuşsa veli bağlantısı da çalışmaz.
create or replace function public.parent_view(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  l    public.parent_links%rowtype;
  p    public.profiles%rowtype;
  d    jsonb;
  st   jsonb;
  sid  text;
  cids jsonb;
begin
  if p_token is null or length(p_token) < 32 then
    return jsonb_build_object('error', 'notfound'); end if;
  select * into l from public.parent_links where token = p_token;
  if not found then return jsonb_build_object('error', 'notfound'); end if;

  select * into p from public.profiles where id = l.coach_id;
  if not found or not p.approved
     or (p.role <> 'admin' and (p.frozen or (p.paid_until is not null and p.paid_until < current_date))) then
    return jsonb_build_object('error', 'inactive'); end if;

  select data into d from public.coach_state where coach_id = l.coach_id;
  if d is null then return jsonb_build_object('error', 'notfound'); end if;

  sid := l.student_id;
  select s into st from jsonb_array_elements(coalesce(d->'students', '[]'::jsonb)) s
   where s->>'id' = sid limit 1;
  if st is null then return jsonb_build_object('error', 'notfound'); end if;

  cids := case when jsonb_typeof(st->'curIds') = 'array' then st->'curIds'
               else jsonb_build_array(st->'curId') end;

  return jsonb_build_object(
    'ok', true,
    'coach', coalesce(nullif(p.full_name, ''), 'Koç'),
    'data', jsonb_build_object(
      'v', 1,
      'active', sid,
      'students',  jsonb_build_array(st - 'notes'),
      'curricula', coalesce((select jsonb_agg(c order by o) from jsonb_array_elements(coalesce(d->'curricula', '[]'::jsonb)) with ordinality x(c, o)
                              where cids ? (c->>'id')), '[]'::jsonb),
      'tasks',     coalesce((select jsonb_agg(t order by o) from jsonb_array_elements(coalesce(d->'tasks', '[]'::jsonb)) with ordinality x(t, o)
                              where t->>'sid' = sid), '[]'::jsonb),
      'questions', coalesce((select jsonb_agg(q order by o) from jsonb_array_elements(coalesce(d->'questions', '[]'::jsonb)) with ordinality x(q, o)
                              where q->>'sid' = sid), '[]'::jsonb),
      'exams',     coalesce((select jsonb_agg(e order by o) from jsonb_array_elements(coalesce(d->'exams', '[]'::jsonb)) with ordinality x(e, o)
                              where e->>'sid' = sid and e->>'done' = 'true'), '[]'::jsonb),
      'progress',  jsonb_build_object(sid, coalesce(d->'progress'->sid, '{}'::jsonb)),
      'plans',     jsonb_build_object(sid, coalesce(d->'plans'->sid, '{"weeks":{}}'::jsonb)),
      'books',     '[]'::jsonb
    )
  );
end $$;

revoke execute on function public.parent_view(text) from public;
grant  execute on function public.parent_view(text) to anon, authenticated;

-- Kontrol: tablo oluştuysa 0 (ya da var olan bağlantı sayısı) görmelisin.
select count(*) as veli_baglantisi_sayisi from public.parent_links;
