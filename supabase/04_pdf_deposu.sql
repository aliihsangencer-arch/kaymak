-- k-Koçluk · 3. aşama: PDF deposu (kitaplar ve sınav kitapçıkları)
-- Supabase > SQL Editor'e yapıştırıp "Run" ile çalıştır. Önce 01 numaralı dosya çalışmış olmalı.
-- Birden fazla kez çalıştırmak güvenlidir.

-- 1) Depo: yalnızca PDF, dosya başına en fazla 50 MB.
--    "public" olması, dosyanın tam adresini bilen kişinin onu açabilmesi demektir; adresler tahmin
--    edilemeyecek kadar uzun ve rastgeledir. Öğrenciler sınav kitapçığını bu sayede açabilir.
--    Depodaki dosyaların listesi dışarıya kapalıdır.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('pdf', 'pdf', true, 52428800, array['application/pdf'])
on conflict (id) do update
  set public = true, file_size_limit = 52428800, allowed_mime_types = array['application/pdf'];

-- 2) Kurallar: her koç yalnızca kendi klasörüne (klasör adı = koçun kimliği) yükler, kendi dosyalarını
--    listeler ve siler. Yönetici tüm dosyaları listeleyebilir.
drop policy if exists pdf_insert_own on storage.objects;
create policy pdf_insert_own on storage.objects for insert to authenticated
  with check (bucket_id = 'pdf'
              and (storage.foldername(name))[1] = auth.uid()::text
              and public.is_approved());

drop policy if exists pdf_select_own on storage.objects;
create policy pdf_select_own on storage.objects for select to authenticated
  using (bucket_id = 'pdf'
         and (((storage.foldername(name))[1] = auth.uid()::text and public.is_approved())
              or public.is_admin()));

drop policy if exists pdf_delete_own on storage.objects;
create policy pdf_delete_own on storage.objects for delete to authenticated
  using (bucket_id = 'pdf'
         and (storage.foldername(name))[1] = auth.uid()::text
         and public.is_approved());

-- Kontrol: id = pdf, public = true görmelisin.
select id, public, file_size_limit from storage.buckets where id = 'pdf';
