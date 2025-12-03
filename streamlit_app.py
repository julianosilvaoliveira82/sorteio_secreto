import streamlit as st
import json
import base64
import hashlib
import time
import random
import urllib.parse
import re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from supabase import create_client, Client

# ==========================================
# CONFIGURAÇÃO E DOCUMENTAÇÃO
# ==========================================
# Este app é uma versão Python/Streamlit do "Amigo Secreto Seguro".
#
# OBJETIVO: Uso recreativo (família/amigos).
# SEGURANÇA: Criptografia AES-256 (CBC) via PyCryptodome.
#            Chaves derivadas do PIN (6 dígitos) usando PBKDF2.
#            Persistência em Supabase (Tabelas 'draws' e 'participants').
#
# FLUXO DE PIN MUTÁVEL:
# 1. Admin gera sorteio -> Todos recebem PIN inicial (Ex: 123456).
# 2. Participante entra -> Deve trocar PIN imediatamente.
# 3. Backend recriptografa o envelope com o novo PIN.
# 4. Admin nunca vê o PIN final.
# 5. Se user perde senha -> Admin usa 'Resetar PIN' (usa admin_recovery_blob).

st.set_page_config(
    page_title="Amigo Secreto Seguro",
    page_icon="🎅",
    layout="centered"
)

# ==========================================
# SUPABASE INTEGRATION
# ==========================================

@st.cache_resource
def get_supabase_client() -> Client:
    """
    Inicializa e cacheia o cliente Supabase usando st.secrets.
    """
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["anon_key"]
        return create_client(url, key)
    except Exception as e:
        st.error(f"Erro ao configurar Supabase: {e}")
        return None

supabase = get_supabase_client()

# --- DB FUNCTIONS ---

def create_draw_in_db(admin_pin: str, reveal_at: int, pairs: list) -> str:
    """
    Cria o sorteio e os participantes no banco.
    pairs: list of dicts { 'ownerName': ..., 'receiverName': ..., 'pin': ... }
    Retorna draw_id (uuid) ou None.
    """
    if not supabase: return None

    try:
        # 1. Create Draw
        draw_data = {
            "admin_pin": admin_pin,
            "reveal_at": datetime.fromtimestamp(reveal_at / 1000).isoformat() if reveal_at else None
        }
        res_draw = supabase.table("draws").insert(draw_data).execute()
        if not res_draw.data: return None
        draw_id = res_draw.data[0]['id']
        
        # 2. Create Participants
        participants_data = []
        for p in pairs:
            # A. Criptografa o target usando o PIN inicial do usuário (acesso dele)
            enc_target = encrypt_string(p['receiverName'], p['pin'])

            # B. Criptografa o target usando o PIN do Admin (backup para reset)
            admin_blob = encrypt_string(p['receiverName'], admin_pin)

            participants_data.append({
                "draw_id": draw_id,
                "name": p['ownerName'],
                "encrypted_target": enc_target,
                "admin_recovery_blob": admin_blob,
                "pin_initial": p['pin'],
                "pin_final": None,
                "must_change_pin": True
            })

        supabase.table("participants").insert(participants_data).execute()
        return draw_id
    except Exception as e:
        st.error(f"Erro ao criar sorteio no banco: {e}")
        return None

def load_draw(draw_id: str, admin_pin: str):
    """
    Carrega um sorteio existente, validando o ID e o PIN do Admin.
    Retorna (draw_data, error_message).
    """
    if not supabase: return None, "Erro de conexão com banco de dados."

    try:
        # 1. Busca o sorteio pelo ID
        # .single() retorna um único objeto ou erro se não encontrar
        res = supabase.table("draws").select("*").eq("id", draw_id).execute()
        
        if not res.data or len(res.data) == 0:
            return None, "Sorteio não encontrado."

        draw = res.data[0]

        # 2. Valida o PIN
        if draw['admin_pin'] != admin_pin:
            return None, "PIN incorreto."

        return draw, None
        
    except Exception as e:
        # Verifica se é erro de UUID inválido
        if "invalid input syntax for type uuid" in str(e):
            return None, "ID inválido."
        return None, f"Erro ao carregar: {str(e)}"

def get_draw_participants(draw_id: str):
    """Retorna lista de participantes de um sorteio."""
    if not supabase: return []
    try:
        res = supabase.table("participants").select("*").eq("draw_id", draw_id).execute()
        return res.data
    except Exception as e:
        st.error(f"Erro ao buscar participantes: {e}")
        return []

def get_participant(p_id: str):
    """Busca um participante pelo ID (UUID)."""
    if not supabase: return None
    try:
        res = supabase.table("participants").select("*, draws(reveal_at)").eq("id", p_id).execute()
        if res.data:
            return res.data[0]
        return None
    except Exception as e:
        # print(f"Erro get_participant: {e}") # Log interno
        return None

def update_participant_pin(p_id: str, new_pin: str, new_encrypted_target: str):
    """
    Atualiza o PIN final e o alvo recriptografado.
    Define must_change_pin = False.
    """
    if not supabase: return False
    try:
        data = {
            "pin_final": new_pin,
            "encrypted_target": new_encrypted_target,
            "must_change_pin": False
        }
        supabase.table("participants").update(data).eq("id", p_id).execute()
        return True
    except Exception as e:
        st.error(f"Erro ao atualizar PIN: {e}")
        return False

def admin_reset_pin_db(p_id: str, new_initial_pin: str, new_encrypted_target: str):
    """
    Admin reseta o PIN.
    Volta para must_change_pin = True.
    Limpa pin_final.
    Atualiza pin_initial e encrypted_target (refeito).
    """
    if not supabase: return False
    try:
        data = {
            "pin_initial": new_initial_pin,
            "pin_final": None,
            "must_change_pin": True,
            "encrypted_target": new_encrypted_target
        }
        supabase.table("participants").update(data).eq("id", p_id).execute()
        return True
    except Exception as e:
        st.error(f"Erro ao resetar PIN: {e}")
        return False

# ==========================================
# CRIPTOGRAFIA (AES-256-CBC + PBKDF2)
# ==========================================

SALT_FIXO = b"AMIGO_SECRETO_SALT_2025"
ITERATIONS = 10000
KEY_SIZE = 32 # 256 bits

def get_key(pin: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), SALT_FIXO, ITERATIONS, dklen=KEY_SIZE)

def encrypt_string(plaintext: str, pin: str) -> str:
    """Criptografa string simples."""
    try:
        data_bytes = plaintext.encode('utf-8')
        key = get_key(pin)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        
        token_data = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        json_token = json.dumps(token_data)
        return base64.urlsafe_b64encode(json_token.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""

def decrypt_string(token: str, pin: str) -> str:
    """Descriptografa para string."""
    try:
        missing_padding = len(token) % 4
        if missing_padding: token += '=' * (4 - missing_padding)
            
        json_token = base64.urlsafe_b64decode(token).decode('utf-8')
        token_data = json.loads(json_token)
        
        iv = base64.b64decode(token_data["iv"])
        ciphertext = base64.b64decode(token_data["ciphertext"])
        key = get_key(pin)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, AES.block_size).decode('utf-8')
    except Exception as e:
        # print(f"Decryption error: {e}")
        return None

# ==========================================
# UTILITÁRIOS LÓGICA
# ==========================================

def clean_names(text):
    """
    Normaliza a lista de nomes:
    1. Remove espaços duplos
    2. Strip
    3. Remove linhas vazias
    4. Capitalização amigável
    """
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        # Remove espaços extras (ex: "  Maria   Silva  " -> "Maria Silva")
        normalized = re.sub(r'\s+', ' ', line).strip()
        if normalized:
            # Capitaliza nome próprio (ex: "maria silva" -> "Maria Silva")
            # Usa .title() mas preserva 'da', 'de' se quiséssemos ser perfeccionistas,
            # mas title() simples é suficiente para requisito.
            cleaned.append(normalized.title())
    return cleaned

def validate_names(names):
    duplicates = set([x for x in names if names.count(x) > 1])
    if duplicates: return False, f"Nomes duplicados: {', '.join(duplicates)}"
    if len(names) < 3: return False, "Mínimo de 3 participantes."
    return True, "OK"

def generate_pin():
    return f"{random.randint(0, 999999):06d}"

def format_date(ts_iso):
    """Formata data ISO para DD/MM/AAAA HH:mm"""
    if not ts_iso: return ""
    try:
        # Substitui Z por +00:00 para compatibilidade com versões antigas do Python se necessário
        dt = datetime.fromisoformat(ts_iso.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y às %H:%M')
    except:
        return ts_iso

# ==========================================
# UI
# ==========================================

def inject_css():
    st.markdown("""
    <style>
    /* Variáveis Globais com a nova paleta */
    :root {
        --bg-color: #F8F5E5;
        --card-color: #1E1E24;
        --text-color: #333333;
        --text-inverted: #F1FAEE;
        --accent-color: #E63946;
        --success-color: #2A9D8F;
        --alert-color: #FFDD99;
        --secondary-btn: #457B9D;
    }

    /* Configuração Geral */
    .stApp {
        background-color: var(--bg-color);
        color: var(--text-color);
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }

    /* Títulos */
    h1, h2, h3 {
        color: var(--accent-color) !important;
        font-weight: 800;
        text-align: center;
        margin-bottom: 20px;
    }

    /* Inputs */
    .stTextInput input, .stTextArea textarea, .stDateInput input, .stTimeInput input {
        background-color: white !important;
        color: #333 !important;
        border: 2px solid #ddd;
        border-radius: 8px;
        padding: 10px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: var(--accent-color) !important;
        box-shadow: 0 0 0 2px rgba(230, 57, 70, 0.2) !important;
    }

    /* Botão Primário */
    div.stButton > button[kind="primary"] {
        background-color: var(--accent-color) !important;
        color: white !important;
        border: none;
        padding: 0.6rem 1.2rem;
        border-radius: 8px;
        font-weight: bold;
        transition: all 0.2s ease;
        width: 100%;
    }
    div.stButton > button[kind="primary"]:hover {
        background-color: #D62839 !important;
        transform: translateY(-2px);
        box-shadow: 0 4px 10px rgba(0,0,0,0.2);
    }

    /* Botão Secundário */
    div.stButton > button[kind="secondary"] {
        background-color: var(--secondary-btn) !important;
        color: white !important;
        border: none;
        padding: 0.6rem 1.2rem;
        border-radius: 8px;
        font-weight: bold;
        transition: all 0.2s ease;
        width: 100%;
    }
    div.stButton > button[kind="secondary"]:hover {
        filter: brightness(1.1);
        transform: translateY(-2px);
        box-shadow: 0 4px 10px rgba(0,0,0,0.2);
    }

    /* Cards Personalizados */
    .custom-card {
        background-color: var(--card-color);
        color: var(--text-inverted);
        padding: 25px;
        border-radius: 12px;
        margin-bottom: 20px;
        box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        text-align: center;
    }
    .custom-card h3, .custom-card h2 { color: var(--alert-color) !important; margin: 0 0 10px 0; }
    .custom-card p { color: #ccc !important; font-size: 0.95rem; }

    /* Rodapé */
    .footer {
        text-align: center;
        color: #999;
        font-size: 12px;
        margin-top: 50px;
        padding: 20px;
        border-top: 1px solid #ddd;
        opacity: 0.8;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background-color: white !important;
        border-radius: 8px;
        color: #333 !important;
        font-weight: 600;
        border: 1px solid #eee;
    }

    /* Centralizar conteúdo */
    [data-testid="stVerticalBlock"] > [style*="flex-direction: column;"] > [data-testid="stVerticalBlock"] {
        align-items: center;
    }

    </style>
    """, unsafe_allow_html=True)

def main():
    inject_css()

    # Roteamento via query params
    # Esperado: ?id=<uuid_participante>
    query_params = st.query_params
    p_id = query_params.get("id", None)

    if p_id:
        view_participant(p_id)
    else:
        view_admin()

    st.markdown("""
    <div class='footer'>
        Amigo Secreto v0.6.0 • PIN Mutável<br/>
        Segurança Reforçada: Admin não vê PIN final.
    </div>
    """, unsafe_allow_html=True)

# --- ADMIN VIEWS ---

def view_admin():
    if 'admin_auth' not in st.session_state: st.session_state.admin_auth = False
    if 'current_draw_id' not in st.session_state: st.session_state.current_draw_id = None
    if 'admin_pin' not in st.session_state: st.session_state.admin_pin = "654321" # Default para Beta

    # 1. Configuração (Novo Sorteio)
    if not st.session_state.current_draw_id:
        st.title("🎅 Configurar Sorteio")
        
        with st.container():
            st.markdown("<p style='text-align:center; color:#555;'>Crie um sorteio e compartilhe a magia do Natal!</p>", unsafe_allow_html=True)
            names_input = st.text_area("Participantes (um por linha)", height=150, placeholder="João\nMaria\nPedro", label_visibility="visible")
            
            col1, col2 = st.columns(2)
            # DATA FORMATO DD/MM/AAAA
            with col1: reveal_date = st.date_input("Dia Revelação", value=None, format="DD/MM/YYYY")
            with col2: reveal_time = st.time_input("Hora Revelação", value=None)
            
            admin_pin_input = st.text_input("PIN Admin (Padrão 654321)", value="654321", max_chars=6, type="password")

            if st.button("🎲 GERAR SORTEIO", type="primary"):
                names = clean_names(names_input)
                valid, msg = validate_names(names)
                if not valid:
                    st.error(msg)
                    return
                
                # Sorteio Local
                pool = names[:]
                random.shuffle(pool)
                while any(n == p for n, p in zip(names, pool)):
                    random.shuffle(pool)

                pairs = []
                for i, name in enumerate(names):
                    pairs.append({
                        'ownerName': name,
                        'receiverName': pool[i],
                        'pin': generate_pin() # PIN Inicial
                    })

                # Salvar DB
                ts_ms = None
                if reveal_date and reveal_time:
                    dt = datetime.combine(reveal_date, reveal_time)
                    ts_ms = int(dt.timestamp() * 1000)

                with st.spinner("Salvando..."):
                    draw_id = create_draw_in_db(admin_pin_input, ts_ms, pairs)
                    if draw_id:
                        st.session_state.current_draw_id = draw_id
                        st.session_state.admin_auth = True
                        st.session_state.admin_pin = admin_pin_input # Guarda PIN do Admin para Recovery
                        st.rerun()
                    else:
                        st.error("Erro ao salvar no banco.")

        st.markdown("---")
        with st.expander("📂 Carregar Sorteio (Admin)"):
            did = st.text_input("ID do Sorteio")
            dpin = st.text_input("PIN Admin para Acesso", type="password")
            if st.button("Carregar", type="secondary"):
                if did and len(dpin) == 6:
                    # CORREÇÃO 2: Implementando load_draw corretamente
                    draw, error_msg = load_draw(did, dpin)

                    if draw:
                        st.session_state.current_draw_id = draw['id']
                        st.session_state.admin_auth = True
                        st.session_state.admin_pin = dpin
                        st.success("Sorteio carregado com sucesso!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(error_msg or "Erro desconhecido.")
                else:
                    st.warning("Preencha ID e PIN corretamente.")

    # 2. Dashboard
    else:
        draw_id = st.session_state.current_draw_id
        st.title("📋 Painel Admin")
        st.markdown(f"<div style='background:#fff; padding:10px; border-radius:8px; border:1px solid #ddd; text-align:center; color:#333; margin-bottom:20px;'>ID Sorteio: <b>{draw_id}</b></div>", unsafe_allow_html=True)
        
        participants = get_draw_participants(draw_id)
        if not participants:
            st.error("Nenhum participante encontrado (ou erro de conexão).")
            if st.button("Voltar"):
                st.session_state.current_draw_id = None
                st.rerun()
            return

        base_url = "https://sorteioapp-2025.streamlit.app"
        
        for p in participants:
            with st.expander(f"👤 {p['name']}", expanded=False):
                link = f"{base_url}/?id={p['id']}"

                # Exibe PIN Inicial se ainda não trocou
                if p['must_change_pin']:
                    pin_display = f"🔑 PIN Inicial: **{p['pin_initial']}**"
                    status = "<span style='color:#E63946; font-weight:bold;'>🟡 Aguardando troca</span>"
                else:
                    pin_display = "🔒 PIN Definido pelo usuário (Oculto)"
                    status = "<span style='color:#2A9D8F; font-weight:bold;'>✅ Protegido</span>"

                msg = f"Olá {p['name']}! 🎄\nSeu link: {link}\nPIN Inicial: {p['pin_initial']}"

                st.markdown(f"Status: {status}", unsafe_allow_html=True)
                st.write(pin_display)
                st.text_input("Link", value=link, key=f"lk_{p['id']}")
                st.code(msg)

                # Botão Resetar
                st.markdown("#### 🛠️ Zona de Perigo")

                # Lógica de Confirmação para evitar cliques acidentais
                if st.button("🔄 Resetar PIN (Gerar Novo)", key=f"rst_{p['id']}", type="primary"):
                    # 1. Recuperar Admin PIN da sessão
                    master_pin = st.session_state.admin_pin

                    # 2. Ler blob de recuperação
                    admin_blob = p.get('admin_recovery_blob')
                    if not admin_blob:
                        st.error("Erro: Este sorteio foi criado numa versão antiga sem recuperação.")
                    else:
                        # 3. Decriptar target usando Admin PIN
                        target_plaintext = decrypt_string(admin_blob, master_pin)

                        if not target_plaintext:
                            st.error("PIN Admin incorreto ou dados corrompidos. Não foi possível recuperar.")
                        else:
                            # 4. Gerar Novo PIN Inicial
                            new_initial = generate_pin()

                            # 5. Encriptar target com novo PIN Inicial
                            new_enc_target = encrypt_string(target_plaintext, new_initial)

                            # 6. Salvar no Banco
                            if admin_reset_pin_db(p['id'], new_initial, new_enc_target):
                                st.success(f"PIN Resetado com Sucesso! Novo PIN: {new_initial}")
                                st.info("Copie o novo PIN e envie para o usuário.")
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error("Falha ao atualizar banco de dados.")

        if st.button("Sair", type="secondary"):
            st.session_state.clear()
            st.rerun()

# --- PARTICIPANT VIEWS ---

def view_participant(p_id):
    # Carregar dados
    p = get_participant(p_id)
    if not p:
        st.error("Link inválido ou participante não encontrado.")
        return

    st.markdown("""
    <div style='background-color: #1E1E24; padding: 10px; border-radius: 8px; text-align: center; margin-bottom: 20px;'>
        <span style='color: #FFCA3A; font-weight: bold;'>🔒 AMBIENTE SEGURO</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.title(f"Olá, {p['name']}!")

    # ESTADO: Auth
    if 'user_auth' not in st.session_state: st.session_state.user_auth = False
    
    # TELA 1: LOGIN
    if not st.session_state.user_auth:
        st.markdown("<p style='text-align:center'>Digite seu PIN para entrar.</p>", unsafe_allow_html=True)
        pin_input = st.text_input("PIN", max_chars=6, type="password", key="login_pin")
        
        if st.button("ENTRAR", type="primary"):
            # Verifica qual PIN usar
            if p['must_change_pin']:
                expected = p['pin_initial']
            else:
                expected = p['pin_final']

            if pin_input == expected:
                st.session_state.user_auth = True
                st.session_state.current_pin = pin_input # Guarda PIN na sessão (memória volátil) para decriptar depois
                st.rerun()
            else:
                st.error("PIN incorreto.")
        return

    # TELA 2: TROCA OBRIGATÓRIA
    if p['must_change_pin']:
        st.warning("⚠️ Por segurança, você deve definir um novo PIN secreto.")
        
        new_pin_1 = st.text_input("Novo PIN (6 dígitos)", max_chars=6, type="password", key="np1")
        new_pin_2 = st.text_input("Confirme o PIN", max_chars=6, type="password", key="np2")
        
        if st.button("DEFINIR SENHA E ABRIR", type="primary"):
            if len(new_pin_1) != 6 or not new_pin_1.isdigit():
                st.error("O PIN deve ter 6 números.")
                return
            if new_pin_1 != new_pin_2:
                st.error("Os PINs não coincidem.")
                return
            if new_pin_1 == p['pin_initial']:
                st.error("O novo PIN deve ser diferente do inicial.")
                return
            
            # 1. Decriptar target com PIN inicial
            target = decrypt_string(p['encrypted_target'], p['pin_initial'])
            if not target:
                st.error("Erro fatal de criptografia. Contate o admin.")
                return

            # 2. Encriptar com NOVO PIN
            new_enc = encrypt_string(target, new_pin_1)
            
            # 3. Salvar
            if update_participant_pin(p['id'], new_pin_1, new_enc):
                st.session_state.current_pin = new_pin_1
                st.success("Senha atualizada com sucesso!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Erro ao salvar no banco.")
        return

    # TELA 3: ENVELOPE (Revelação)

    # Check data revelação
    # draws(reveal_at) vem no join? Sim, fiz select "*, draws(reveal_at)" mas supabase-py retorna nested dict
    reveal_at_iso = p.get('draws', {}).get('reveal_at')

    if reveal_at_iso:
        reveal_dt = datetime.fromisoformat(reveal_at_iso.replace('Z', '+00:00'))
        if datetime.now(reveal_dt.tzinfo) < reveal_dt:
             st.markdown(f"""
            <div class="custom-card" style="background-color: #FFF3CD; border: 2px solid #FFCA3A;">
                <h3 style="color: #856404 !important;">⏳ Psiu! Ainda não...</h3>
                <p style="color: #856404 !important; text-align: center;">A revelação será em:</p>
                <h2 style="color: #D64045 !important;">{reveal_dt.strftime('%d/%m/%Y %H:%M')}</h2>
            </div>
            """, unsafe_allow_html=True)
             return

    # Decriptar Envelope
    current_pin = st.session_state.current_pin
    target_name = decrypt_string(p['encrypted_target'], current_pin)

    if not target_name:
        st.error("Não foi possível abrir o envelope. O PIN na sessão pode estar inválido. Faça login novamente.")
        if st.button("Sair"):
            st.session_state.clear()
            st.rerun()
        return

    st.balloons()
    st.markdown("""
        <div class="custom-card" style="background-color: #E63946; border: 2px solid #D62839;">
            <h3 style="color: white !important;">🎉 VOCÊ TIROU:</h3>
            <h1 style="color: #FFCA3A !important; font-size: 3em;">{}</h1>
            <p style="color: white !important; text-align: center;">🤫 Shhh! Guarde segredo.</p>
        </div>
        """.format(target_name), unsafe_allow_html=True)

    # BOTÃO TROCAR PIN (Voluntário)
    with st.expander("🔒 Trocar meu PIN"):
        cp_old = st.text_input("PIN Atual", type="password", key="cp_old")
        cp_new = st.text_input("Novo PIN", type="password", max_chars=6, key="cp_new")
        
        if st.button("Alterar PIN", type="secondary"):
            if cp_old != current_pin:
                st.error("PIN atual incorreto.")
                return
            if len(cp_new) != 6 or not cp_new.isdigit():
                st.error("Novo PIN inválido.")
                return

            new_enc_target = encrypt_string(target_name, cp_new)
            if update_participant_pin(p['id'], cp_new, new_enc_target):
                st.session_state.current_pin = cp_new
                st.success("PIN alterado!")
                time.sleep(1)
                st.rerun()

if __name__ == "__main__":
    main()
