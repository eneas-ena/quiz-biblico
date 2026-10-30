-- ============================================================
-- QUIZ BÍBLICO — Segurança (versão 2)
--
-- O que muda:
--  * Ninguém lê a tabela "jogadores" direto (nem o código do PIN).
--  * O PIN é conferido AQUI, no banco, com limite de 5 erros a cada
--    15 minutos por jogador (impede adivinhar o PIN no "chute").
--  * Os pontos só são salvos por quem entrou com o PIN certo.
--  * A área do administrador usa o login do Bispo (função eh_dono,
--    criada pelo script das Despesas, que já foi rodado).
--
-- Cole no SQL Editor do Supabase e clique em RUN. Pode rodar de novo.
-- Os jogadores, PINs e pontos atuais são mantidos.
-- ============================================================

-- 1) Tabela jogadores: fechada para todos, aberta só para o dono (admin)
alter table public.jogadores enable row level security;

do $$
declare p record;
begin
  for p in select policyname from pg_policies
           where schemaname = 'public' and tablename = 'jogadores'
  loop
    execute format('drop policy %I on public.jogadores', p.policyname);
  end loop;
end $$;

revoke all on public.jogadores from anon, authenticated;
grant select, insert, update, delete on public.jogadores to authenticated;
grant all on public.jogadores to service_role;

create policy "quiz_admin_tudo" on public.jogadores for all to authenticated
  using (public.eh_dono()) with check (public.eh_dono());

-- 2) Sessões de jogo e tentativas de PIN (só o banco mexe nelas)
create table if not exists public.quiz_sessoes (
  token uuid primary key default gen_random_uuid(),
  jogador_id text not null,
  criada_em timestamptz not null default now()
);
create table if not exists public.quiz_tentativas (
  jogador_id text not null,
  em timestamptz not null default now()
);
create index if not exists idx_quiz_tent on public.quiz_tentativas (jogador_id, em);
alter table public.quiz_sessoes   enable row level security;
alter table public.quiz_tentativas enable row level security;
revoke all on public.quiz_sessoes, public.quiz_tentativas from anon, authenticated;
grant all on public.quiz_sessoes, public.quiz_tentativas to service_role;

-- 3) Lista de jogadores para a tela inicial e o ranking (SEM o PIN)
create or replace function public.quiz_lista()
returns table (id text, nome text, avatar text, total numeric, per_level jsonb, peak numeric)
language sql stable security definer
set search_path = public
as $$
  select j.id::text, j.nome::text, j.avatar::text, coalesce(j.total,0)::numeric,
         coalesce(to_jsonb(j.per_level), '{}'::jsonb), coalesce(j.peak,0)::numeric
  from public.jogadores j
  order by j.total desc nulls last
$$;

-- 4) Entrar: confere o PIN e devolve um "crachá" de jogo
create or replace function public.quiz_entrar(p_id text, p_hash text)
returns uuid
language plpgsql volatile security definer
set search_path = public
as $$
declare
  certo text;
  erros int;
  t uuid;
begin
  delete from public.quiz_tentativas where em < now() - interval '1 day';
  select count(*) into erros from public.quiz_tentativas
    where jogador_id = p_id and em > now() - interval '15 minutes';
  if erros >= 5 then
    raise exception 'BLOQUEADO' using errcode = 'P0001';
  end if;

  select j.pin_hash into certo from public.jogadores j where j.id::text = p_id;
  if certo is null or p_hash is null or certo <> p_hash then
    insert into public.quiz_tentativas (jogador_id) values (p_id);
    return null;
  end if;

  delete from public.quiz_tentativas where jogador_id = p_id;
  delete from public.quiz_sessoes where criada_em < now() - interval '60 days';
  insert into public.quiz_sessoes (jogador_id) values (p_id) returning token into t;
  return t;
end $$;

-- 5) Salvar pontos: só com o crachá do próprio jogador
create or replace function public.quiz_salvar(p_token uuid, p_total numeric, p_per_level jsonb, p_peak numeric)
returns boolean
language plpgsql volatile security definer
set search_path = public
as $$
declare jid text;
begin
  select s.jogador_id into jid from public.quiz_sessoes s
    where s.token = p_token and s.criada_em > now() - interval '60 days';
  if jid is null then return false; end if;
  update public.jogadores j
     set total = p_total, per_level = p_per_level, peak = p_peak
   where j.id::text = jid;
  return true;
end $$;

-- 6) Sair: invalida o crachá
create or replace function public.quiz_sair(p_token uuid)
returns void
language sql volatile security definer
set search_path = public
as $$
  delete from public.quiz_sessoes where token = p_token
$$;

revoke all on function public.quiz_lista(), public.quiz_entrar(text,text),
  public.quiz_salvar(uuid,numeric,jsonb,numeric), public.quiz_sair(uuid) from public;
grant execute on function public.quiz_lista(), public.quiz_entrar(text,text),
  public.quiz_salvar(uuid,numeric,jsonb,numeric), public.quiz_sair(uuid) to anon, authenticated;

-- Conferência: deve listar os jogadores (sem PIN)
select nome, total from public.quiz_lista();
