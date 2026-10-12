-- ふたりの財布：家計ごとにデータを分ける（1回だけ実行すればOK。再実行しても安全です）

-- 1) 家計と参加者の表
create table if not exists public.households (
  id uuid primary key default gen_random_uuid(),
  invite_code text not null unique default upper(substr(md5(random()::text || clock_timestamp()::text), 1, 10)),
  created_at timestamptz not null default now()
);
create table if not exists public.members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (household_id, user_id),
  unique (user_id)
);
alter table public.households enable row level security;
alter table public.members enable row level security;

-- 2) 「この家計の参加者か」を調べる関数
create or replace function public.is_member(hid uuid)
returns boolean language sql stable security definer set search_path = ''
as $$ select exists (select 1 from public.members where household_id = hid and user_id = (select auth.uid())) $$;

-- 3) 1つの家計に参加できるのは2人まで
create or replace function public.members_limit()
returns trigger language plpgsql set search_path = ''
as $$ begin
  if (select count(*) from public.members where household_id = new.household_id) >= 2 then
    raise exception 'household_full';
  end if;
  return new;
end $$;
drop trigger if exists members_limit on public.members;
create trigger members_limit before insert on public.members for each row execute function public.members_limit();

-- 4) いまあるデータを、いまの2人の家計として引き継ぐ
alter table public.docs add column if not exists household_id uuid;
do $$
declare hid uuid;
begin
  if exists (select 1 from public.docs where household_id is null) then
    insert into public.households default values returning id into hid;
    insert into public.members (household_id, user_id)
      select hid, u.id from (select id from auth.users order by created_at limit 2) u
      where not exists (select 1 from public.members m where m.user_id = u.id);
    update public.docs set household_id = hid where household_id is null;
  end if;
end $$;
alter table public.docs alter column household_id set not null;
do $$
begin
  if exists (select 1 from pg_constraint where conrelid = 'public.docs'::regclass and conname = 'docs_pkey' and pg_get_constraintdef(oid) = 'PRIMARY KEY (key)') then
    alter table public.docs drop constraint docs_pkey;
    alter table public.docs add constraint docs_pkey primary key (household_id, key);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'docs_household_fk') then
    alter table public.docs add constraint docs_household_fk foreign key (household_id) references public.households(id) on delete cascade;
  end if;
end $$;

-- 5) 閲覧・書き込みは、その家計の参加者だけ
alter table public.docs enable row level security;
drop policy if exists "docs_select" on public.docs;
drop policy if exists "docs_insert" on public.docs;
drop policy if exists "docs_update" on public.docs;
create policy "docs_select" on public.docs for select to authenticated using (public.is_member(household_id));
create policy "docs_insert" on public.docs for insert to authenticated with check (public.is_member(household_id));
create policy "docs_update" on public.docs for update to authenticated using (public.is_member(household_id)) with check (public.is_member(household_id));
drop policy if exists "members_select" on public.members;
create policy "members_select" on public.members for select to authenticated using (public.is_member(household_id));
drop policy if exists "households_select" on public.households;
create policy "households_select" on public.households for select to authenticated using (public.is_member(id));

-- 6) 家計を作る・参加する・自分の家計を調べる
create or replace function public.my_household()
returns setof public.households language sql stable security definer set search_path = ''
as $$ select h.* from public.households h join public.members m on m.household_id = h.id where m.user_id = (select auth.uid()) limit 1 $$;

create or replace function public.create_household()
returns public.households language plpgsql security definer set search_path = ''
as $$
declare h public.households;
begin
  if (select auth.uid()) is null then raise exception 'not_authenticated'; end if;
  if exists (select 1 from public.members where user_id = (select auth.uid())) then raise exception 'already_member'; end if;
  insert into public.households default values returning * into h;
  insert into public.members (household_id, user_id) values (h.id, (select auth.uid()));
  return h;
end $$;

create or replace function public.join_household(code text)
returns public.households language plpgsql security definer set search_path = ''
as $$
declare h public.households;
begin
  if (select auth.uid()) is null then raise exception 'not_authenticated'; end if;
  if exists (select 1 from public.members where user_id = (select auth.uid())) then raise exception 'already_member'; end if;
  select * into h from public.households where invite_code = upper(trim(code));
  if not found then raise exception 'invalid_code'; end if;
  insert into public.members (household_id, user_id) values (h.id, (select auth.uid()));
  return h;
end $$;

-- 7) 権限
revoke all on function public.is_member(uuid) from public, anon;
revoke all on function public.my_household() from public, anon;
revoke all on function public.create_household() from public, anon;
revoke all on function public.join_household(text) from public, anon;
grant execute on function public.is_member(uuid) to authenticated;
grant execute on function public.my_household() to authenticated;
grant execute on function public.create_household() to authenticated;
grant execute on function public.join_household(text) to authenticated;
grant select on public.households, public.members to authenticated;
grant select, insert, update on public.docs to authenticated;

-- 8) 最後の参加者が退会・削除されたときだけ、空になった家計と記録を片付ける
create or replace function public.cleanup_household_when_last_member_leaves()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  delete from public.households h
  where h.id = old.household_id
    and not exists (
      select 1 from public.members m where m.household_id = old.household_id
    );
  return old;
end $$;
revoke all on function public.cleanup_household_when_last_member_leaves() from public, anon, authenticated;
drop trigger if exists members_cleanup_empty_household on public.members;
create trigger members_cleanup_empty_household
after delete on public.members
for each row execute function public.cleanup_household_when_last_member_leaves();

-- 9) 変更をすぐ相手の画面に届ける設定（すでにあれば何もしません）
do $$
begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null;
end $$;
