-- Demo table written to by the depot-issuer example.
-- Demonstrates RLS scoped by issuer and role.

create table public.widgets (
  id            bigserial primary key,
  name          text not null,
  owner_issuer  text not null,
  created_at    timestamptz not null default now()
);

alter table public.widgets enable row level security;

-- Anyone with role widgets_writer can INSERT, and the row's owner_issuer
-- must equal their own iss claim. Issuers cannot insert on behalf of others.
create policy widgets_insert on public.widgets
  for insert to authenticated
  with check (
    auth.has_role('widgets_writer')
    and owner_issuer = auth.issuer()
  );

-- Only the owning issuer can update or delete its rows.
create policy widgets_update on public.widgets
  for update to authenticated
  using (auth.is_issuer(owner_issuer))
  with check (auth.is_issuer(owner_issuer));

create policy widgets_delete on public.widgets
  for delete to authenticated
  using (auth.is_issuer(owner_issuer));

-- Reads are open to any authenticated caller in this demo. Real deployments
-- would scope this further.
create policy widgets_select on public.widgets
  for select to authenticated
  using (true);

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.widgets to authenticated;
grant usage on sequence public.widgets_id_seq to authenticated;
