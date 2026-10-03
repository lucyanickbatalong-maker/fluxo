-- ============================================================
-- FLUXO · Schéma de base de données (PostgreSQL / Supabase)
-- À exécuter : Supabase Dashboard → SQL Editor → New query → coller → Run
-- Crée : tables, règles d'accès (RLS), fonctions serveur, temps réel
-- RÉ-EXÉCUTABLE sans erreur : peuvent être relancées sans « already exists »
-- ============================================================

-- ------------------------------------------------------------
-- 1. BOXES (tous des boxes de consultation / prise en charge)
-- ------------------------------------------------------------
create table if not exists boxes (
  id           int primary key check (id between 1 and 99),
  name         text not null,
  state        text not null default 'closed'
               check (state in ('closed','idle','ringing','busy','pause')),
  auto_next    boolean not null default true,
  current_code text,
  updated_at   timestamptz not null default now()
);

insert into boxes (id, name) values
  (1,'Box 1'),(2,'Box 2'),(3,'Box 3'),(4,'Box 4'),(5,'Box 5')
on conflict (id) do nothing;

-- ------------------------------------------------------------
-- 2. TICKETS (numérotation continue A01 → Z99)
--    svc : 'consult' = Consultation · 'care' = Prise en charge
-- ------------------------------------------------------------
create table if not exists tickets (
  id         bigint generated always as identity primary key,
  code       text not null unique,
  svc        text not null check (svc in ('consult','care')),
  prio       boolean not null default false,
  taken_at   timestamptz not null default now(),
  state      text not null default 'waiting'
             check (state in ('waiting','called','serving','done')),
  box_id     int references boxes(id),
  called_at  timestamptz,
  started_at timestamptz,
  ended_at   timestamptz,
  absent     boolean not null default false
);

create index if not exists tickets_waiting_idx on tickets (taken_at) where state = 'waiting';

-- ------------------------------------------------------------
-- 3. COMPTEUR GLOBAL (A01 → A99, B01 → … → Z99, puis retour A01)
-- ------------------------------------------------------------
create table if not exists app_meta (
  key text primary key,
  n   bigint not null default 0
);
insert into app_meta (key, n) values ('ticket_seq', 0) on conflict do nothing;

-- ------------------------------------------------------------
-- 4. PERSONNEL (rôles : pro = box · sup = régie)
--    Un ligne par utilisateur Supabase Auth (id = auth.users.id)
-- ------------------------------------------------------------
create table if not exists staff (
  id        uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  role      text not null check (role in ('pro','sup')),
  box_id    int references boxes(id),
  active    boolean not null default true
);

-- ------------------------------------------------------------
-- 5. JOURNAL D'AUDIT (qui a fait quoi, quand)
-- ------------------------------------------------------------
create table if not exists audit_log (
  id      bigint generated always as identity primary key,
  actor   text,
  action  text not null,
  details jsonb,
  at      timestamptz not null default now()
);

-- ============================================================
-- FONCTIONS SERVEUR (exécutées côté base, jamais dans le navigateur)
-- ============================================================

-- Le visiteur authentifié est-il un membre du personnel actif ?
create or replace function is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from staff where id = auth.uid() and active);
$$;

-- Le visiteur authentifié est-il superviseur ?
create or replace function is_supervisor() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from staff where id = auth.uid() and active and role = 'sup');
$$;

-- Numérotation atomique : la borne appelle cette fonction (publique)
create or replace function issue_ticket(p_svc text, p_prio boolean default false)
returns text language plpgsql security definer set search_path = public as $$
declare
  v_n    bigint;
  v_code text;
begin
  if p_svc not in ('consult','care') then
    raise exception 'Motif de visite inconnu';
  end if;
  update app_meta set n = (n + 1) % (26 * 99) where key = 'ticket_seq' returning n into v_n;
  v_code := chr(65 + (v_n / 99)) || lpad(((v_n % 99) + 1)::text, 2, '0');
  insert into tickets (code, svc, prio) values (v_code, p_svc, p_prio);
  insert into audit_log (action, details)
    values ('issue_ticket', jsonb_build_object('code', v_code, 'svc', p_svc, 'prio', p_prio));
  return v_code;
end $$;

-- Appel du prochain ticket par un box (atomique, anti-collision :
-- deux boxes qui appellent en même temps ne reçoivent jamais le même ticket)
create or replace function call_next(p_box int) returns text
language plpgsql security definer set search_path = public as $$
declare
  v_ticket tickets;
begin
  if not is_staff() then raise exception 'Accès réservé au personnel'; end if;
  select * into v_ticket from tickets
    where state = 'waiting'
    order by prio desc, taken_at asc
    limit 1 for update skip locked;
  if v_ticket.id is null then
    update boxes set state = 'idle', current_code = null, updated_at = now() where id = p_box;
    return null;
  end if;
  update tickets set state = 'called', box_id = p_box, called_at = now() where id = v_ticket.id;
  update boxes  set state = 'ringing', current_code = v_ticket.code, updated_at = now() where id = p_box;
  insert into audit_log (actor, action, details)
    values (auth.uid()::text, 'call_next', jsonb_build_object('box', p_box, 'ticket', v_ticket.code));
  return v_ticket.code;
end $$;

-- Réinitialisation de la journée (réservée au superviseur)
create or replace function reset_day() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_supervisor() then raise exception 'Superviseur requis'; end if;
  delete from tickets;
  update boxes set state = 'closed', current_code = null;
  update app_meta set n = 0 where key = 'ticket_seq';
  insert into audit_log (actor, action) values (auth.uid()::text, 'reset_day');
end $$;

-- Droits d'exécution des fonctions
grant execute on function issue_ticket(text, boolean) to anon, authenticated;
grant execute on function call_next(int)              to authenticated;
grant execute on function reset_day()                 to authenticated;

-- ============================================================
-- RÈGLES D'ACCÈS (RLS) — la clé publique « anon » est exposée
-- dans le navigateur : c'est ICI que se joue la sécurité.
-- ============================================================
alter table tickets   enable row level security;
alter table boxes     enable row level security;
alter table staff     enable row level security;
alter table audit_log enable row level security;
alter table app_meta  enable row level security;

-- Lecture publique : l'afficheur et la borne n'ont pas de compte
drop policy if exists "lecture publique tickets" on tickets;
drop policy if exists "lecture publique boxes"   on boxes;
create policy "lecture publique tickets" on tickets for select using (true);
create policy "lecture publique boxes"   on boxes   for select using (true);

-- Écriture réservée au personnel
drop policy if exists "staff maj tickets" on tickets;
create policy "staff maj tickets" on tickets for update
  using (is_staff());
drop policy if exists "maj box par son titulaire ou la régie" on boxes;
create policy "maj box par son titulaire ou la régie" on boxes for update
  using (is_supervisor() or exists (
    select 1 from staff s where s.id = auth.uid() and s.box_id = boxes.id and s.active
  ));

-- staff : chacun lit son propre profil ; la régie lit tout
drop policy if exists "profil propre" on staff;
create policy "profil propre" on staff for select
  using (id = auth.uid() or is_supervisor());

-- audit : lecture par la régie uniquement (l'écriture passe par les fonctions)
drop policy if exists "audit lecture régie" on audit_log;
create policy "audit lecture régie" on audit_log for select using (is_supervisor());

-- app_meta : aucun accès direct au client (les fonctions contournent via SECURITY DEFINER)

-- ============================================================
-- TEMPS RÉEL : les écrans se mettent à jour sans recharger
-- (sinon : Dashboard → Database → Replication → activer tickets & boxes)
-- ============================================================
do $$ begin
  alter publication supabase_realtime add table tickets;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table boxes;
exception when duplicate_object then null; end $$;
