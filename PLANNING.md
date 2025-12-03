# Jules - Planejamento de Implementação e QA

## 1. Backlog Prioritário (P0/P1)

### P0 - Crítico

**User Story 1: Persistência e Status Detalhado**
*   **Como** Admin, **quero** ver o status detalhado de cada participante, **para** saber quem já trocou o PIN, quem já abriu o envelope e quem está bloqueado.
*   *Critérios de Aceitação*:
    *   Tabela no painel Admin mostrando: Nome, Status PIN (Inicial/Privado), Envelope Aberto (Sim/Não), Tentativas Falhas.
    *   Dados persistidos no Supabase.

**User Story 2: Rate Limiting e Bloqueio**
*   **Como** Sistema, **quero** bloquear tentativas excessivas de PIN, **para** impedir ataques de força bruta.
*   *Critérios de Aceitação*:
    *   5 erros consecutivos: Bloqueio de 5 minutos.
    *   10 erros acumulados (resetar após sucesso): Bloqueio de 15 minutos.
    *   Mensagem amigável para o usuário ("Muitas tentativas. Tente novamente em X minutos").

### P1 - Importante

**User Story 3: UX de Formulários**
*   **Como** Admin, **quero** preencher os dados do sorteio e enviar apenas ao clicar no botão, **para** evitar recargas acidentais.
*   *Critérios de Aceitação*:
    *   Uso de `st.form` na tela de configuração.
    *   Botão "Gerar Sorteio" explícito.

**User Story 4: Timezones Corretos**
*   **Como** Usuário Brasileiro, **quero** ver datas e horários no meu fuso (Brasília), **para** não confundir o momento da revelação.
*   *Critérios de Aceitação*:
    *   Inputs e Exibições usando `America/Sao_Paulo`.

## 2. Arquitetura e Modelos de Dados

### Alterações no Schema (Supabase/Postgres)

**Tabela `participants` (Update):**
| Coluna | Tipo | Descrição |
| :--- | :--- | :--- |
| `opened_at` | `timestamptz` | Data/Hora da primeira abertura do envelope. |
| `failed_attempts` | `int` | Contador de tentativas erradas de PIN. |
| `locked_until` | `timestamptz` | Timestamp até quando o usuário está bloqueado. |
| `last_activity_at` | `timestamptz` | Última interação (sucesso ou falha). |

### Serviços (Lógica em `streamlit_app.py`)

*   `RateLimitService`: Verifica `locked_until`, incrementa `failed_attempts`, define bloqueios.
*   `AuditService`: Atualiza `last_activity_at` e `opened_at`.

## 3. Plano de Implementação

1.  **Migration**: Atualizar `db_schema_v2.sql` e rodar comandos SQL (manualmente ou via código se possível) para adicionar colunas.
2.  **Backend Logic**:
    *   Atualizar `get_participant` para trazer novos campos.
    *   Implementar lógica de bloqueio em `view_participant`.
    *   Implementar registro de abertura de envelope.
3.  **Frontend Admin**:
    *   Criar `dataframe` ou tabela visual com os status dos participantes.
4.  **Frontend Config**:
    *   Envolver inputs em `st.form`.
5.  **Timezone**:
    *   Configurar `pytz('America/Sao_Paulo')` globalmente.

## 4. Plano de Testes

**Teste Manual 1: Rate Limiting**
1.  Acessar link de participante.
2.  Errar PIN 5 vezes.
3.  Verificar mensagem de bloqueio (5 min).
4.  Tentar novamente antes de 5 min -> Deve continuar bloqueado.

**Teste Manual 2: Auditoria Admin**
1.  Participante entra, troca PIN e abre envelope.
2.  Admin recarrega painel.
3.  Verificar se coluna "Envelope Aberto" está marcada e "PIN" indica "Privado".

**Teste Manual 3: Fuso Horário**
1.  Configurar revelação para hoje às 23:59 (Brasília).
2.  Verificar se o countdown/data aparece correto no card de espera.

## 5. Checklist de Release

*   [ ] Dependência `pytz` instalada.
*   [ ] Colunas novas criadas no Banco de Dados.
*   [ ] Teste de bloqueio verificado.
*   [ ] Formatação de data validada (DD/MM/YYYY).
