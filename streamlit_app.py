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
        res = supabase.table("draws").select("*").eq("id", draw_id).execute()
        
        if not res.data or len(res.data) == 0:
            return None, "Sorteio não encontrado."

        draw = res.data[0]

        # 2. Valida o PIN
        if draw['admin_pin'] != admin_pin:
            return None, "PIN incorreto."

        return draw, None
        
    except Exception as e:
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
    """
    Valida regras:
    1. Mínimo 3 participantes
    2. Sem duplicatas
    """
    if len(names) < 3:
        return False, "É necessário ter pelo menos 3 participantes para um sorteio válido."

    # Case insensitive check for duplicates just in case
    names_lower = [n.lower() for n in names]
    duplicates = set([x for x in names if names_lower.count(x.lower()) > 1])

    if duplicates:
        return False, f"Você tem nomes duplicados: {', '.join(duplicates)}. Corrija antes de gerar o sorteio."

    return True, "OK"

def generate_pin():
    return f"{random.randint(0, 999999):06d}"

def generate_derangement(names):
    """
    Gera um sorteio válido onde ninguém tira a si mesmo (Derangement).
    Tenta embaralhar até encontrar uma permutação válida.
    """
    pool = names[:]
    max_attempts = 10000
    
    for _ in range(max_attempts):
        random.shuffle(pool)
        # Verifica se alguém tirou a si mesmo
        if all(n != p for n, p in zip(names, pool)):
            return pool
            
    return None

def format_date(ts_iso):
    """Formata data ISO para DD/MM/AAAA HH:mm"""
    if not ts_iso: return ""
    try:
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
    /*
       PALETA MODERNA E ELEGANTE
       Fundo: #F7F5EB (Creme suave)
       Card Principal: #243447 (Azul Grafite Profundo)
       Highlight: #1E90FF (Azul Dodger Moderno)
       Accent: #E63946 (Vermelho Suave)
    */
    :root {
        --bg-color: #F7F5EB;
        --card-bg: #243447;
        --card-text: #FFFFFF;
        --accent-color: #E63946;
        --highlight-color: #1E90FF;
        --shhh-bg: #FFE8A0;
        --shhh-text: #333333;
    }

    /* Global */
    .stApp {
        background-color: var(--bg-color);
        color: #333;
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }

    /* Headers */
    h1, h2, h3 {
        color: var(--accent-color) !important;
        font-weight: 700;
        text-align: center;
    }

    /* CARD DE REVELAÇÃO (Novo Estilo) */
    .reveal-card {
        background-color: var(--card-bg);
        color: var(--card-text);
        padding: 40px 20px;
        border-radius: 16px;
        text-align: center;
        box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        margin: 20px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 15px;
    }

    .reveal-title {
        color: #A0AAB5;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-size: 14px;
        font-weight: 600;
        margin: 0;
    }

    .name-badge {
        background-color: var(--highlight-color);
        color: white;
        font-size: 28px;
        font-weight: 800;
        padding: 15px 30px;
        border-radius: 50px;
        box-shadow: 0 4px 10px rgba(30, 144, 255, 0.4);
        margin: 10px 0;
        display: inline-block;
    }

    .shhh-box {
        background-color: var(--shhh-bg);
        color: var(--shhh-text);
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 14px;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        margin-top: 10px;
    }

    /* Card Padrão (Admin/Login) */
    .standard-card {
        background-color: white;
        padding: 25px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        margin-bottom: 20px;
        text-align: center;
        border: 1px solid #EAEAEA;
    }

    /* Inputs */
    .stTextInput input, .stTextArea textarea, .stDateInput input, .stTimeInput input {
        border-radius: 8px;
        border: 1px solid #DDD;
        padding: 10px;
    }
    .stTextInput input:focus {
        border-color: var(--highlight-color) !important;
        box-shadow: 0 0 0 2px rgba(30, 144, 255, 0.2) !important;
    }

    /* Botões */
    div.stButton > button[kind="primary"] {
        background-color: var(--accent-color) !important;
        color: white !important;
        border-radius: 8px;
        border: none;
        padding: 0.6rem 1.2rem;
        font-weight: 700;
        transition: transform 0.1s;
    }
    div.stButton > button[kind="primary"]:hover {
        transform: translateY(-2px);
        background-color: #D62839 !important;
    }

    div.stButton > button[kind="secondary"] {
        background-color: white !important;
        color: #555 !important;
        border: 1px solid #DDD !important;
        border-radius: 8px;
        font-weight: 600;
    }
    div.stButton > button[kind="secondary"]:hover {
        border-color: #999 !important;
        color: #333 !important;
    }

    /* Footer */
    .footer {
        text-align: center;
        font-size: 12px;
        color: #AAA;
        margin-top: 60px;
        padding-top: 20px;
        border-top: 1px solid #EAEAEA;
    }

    /* Ajustes de layout */
    .block-container {
        padding-top: 3rem;
        padding-bottom: 3rem;
        max-width: 600px;
    }
    </style>
    """, unsafe_allow_html=True)

def main():
    inject_css()

    query_params = st.query_params
    p_id = query_params.get("id", None)

    if p_id:
        view_participant(p_id)
    else:
        view_admin()

    st.markdown("""
    <div class='footer'>
        Amigo Secreto v0.7.0 • Design Premium<br/>
        Segurança Reforçada: Admin não vê PIN final.
    </div>
    """, unsafe_allow_html=True)

# --- ADMIN VIEWS ---

def view_admin():
    if 'admin_auth' not in st.session_state: st.session_state.admin_auth = False
    if 'current_draw_id' not in st.session_state: st.session_state.current_draw_id = None
    if 'admin_pin' not in st.session_state: st.session_state.admin_pin = "654321"

    if not st.session_state.current_draw_id:
        st.title("🎅 Configurar Sorteio")
        
        with st.container():
            st.markdown("<p style='text-align:center; color:#666; margin-bottom:30px;'>Crie uma experiência mágica e organizada.</p>", unsafe_allow_html=True)

            names_input = st.text_area("Participantes (um por linha)", height=150, placeholder="João\nMaria\nPedro", label_visibility="visible")
            
            col1, col2 = st.columns(2)
            with col1: reveal_date = st.date_input("Dia Revelação", value=None, format="DD/MM/YYYY")
            with col2: reveal_time = st.time_input("Hora Revelação", value=None)
            
            admin_pin_input = st.text_input("PIN Admin (Padrão 654321)", value="654321", max_chars=6, type="password")

            if st.button("🎲 GERAR SORTEIO", type="primary"):
                # 1. Normalizar nomes
                names = clean_names(names_input)
                
                # 2. Validar Regras (Min 3, Sem Duplicados)
                valid, msg = validate_names(names)
                if not valid:
                    st.error(msg)
                    return
                
                # 3. Sorteio (Derangement - Ciclo Fechado ou Permutação válida)
                pool = generate_derangement(names)

                if not pool:
                    st.error("Não foi possível gerar uma combinação válida. Tente novamente.")
                    return

                # 4. Preparar Pares
                pairs = []
                for i, name in enumerate(names):
                    pairs.append({
                        'ownerName': name,
                        'receiverName': pool[i],
                        'pin': generate_pin() # PIN Inicial
                    })

                # 5. Salvar DB
                ts_ms = None
                if reveal_date and reveal_time:
                    dt = datetime.combine(reveal_date, reveal_time)
                    ts_ms = int(dt.timestamp() * 1000)

                with st.spinner("Gerando envelopes seguros..."):
                    draw_id = create_draw_in_db(admin_pin_input, ts_ms, pairs)
                    if draw_id:
                        st.session_state.current_draw_id = draw_id
                        st.session_state.admin_auth = True
                        st.session_state.admin_pin = admin_pin_input
                        st.rerun()
                    else:
                        st.error("Erro ao salvar no banco.")

        st.markdown("---")
        with st.expander("📂 Carregar Sorteio (Admin)"):
            did = st.text_input("ID do Sorteio")
            dpin = st.text_input("PIN Admin para Acesso", type="password")
            if st.button("Carregar", type="secondary"):
                if did and len(dpin) == 6:
                    draw, error_msg = load_draw(did, dpin)
                    if draw:
                        st.session_state.current_draw_id = draw['id']
                        st.session_state.admin_auth = True
                        st.session_state.admin_pin = dpin
                        st.success("Sorteio carregado!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(error_msg or "Erro desconhecido.")
                else:
                    st.warning("Preencha ID e PIN corretamente.")

    else:
        # DASHBOARD
        draw_id = st.session_state.current_draw_id
        st.title("📋 Painel Admin")
        st.markdown(f"<div style='text-align:center; color:#777; font-size:14px; margin-bottom:20px;'>ID: <code>{draw_id}</code></div>", unsafe_allow_html=True)
        
        participants = get_draw_participants(draw_id)
        if not participants:
            st.error("Erro ao buscar dados.")
            if st.button("Voltar"):
                st.session_state.current_draw_id = None
                st.rerun()
            return

        base_url = "https://sorteioapp-2025.streamlit.app"
        
        for p in participants:
            with st.expander(f"👤 {p['name']}", expanded=False):
                link = f"{base_url}/?id={p['id']}"

                if p['must_change_pin']:
                    pin_display = f"🔑 PIN Inicial: **{p['pin_initial']}**"
                    status = "<span style='color:#E63946; font-weight:bold;'>🟡 Aguardando troca</span>"
                else:
                    pin_display = "🔒 PIN Definido (Privado)"
                    status = "<span style='color:#2A9D8F; font-weight:bold;'>✅ Protegido</span>"

                msg = f"Olá {p['name']}! 🎄\nSeu link: {link}\nPIN Inicial: {p['pin_initial']}"

                st.markdown(f"Status: {status}", unsafe_allow_html=True)
                st.markdown(pin_display)
                st.text_input("Link", value=link, key=f"lk_{p['id']}")
                st.code(msg)

                st.markdown("#### 🛠️ Zona de Perigo")
                if st.button("🔄 Resetar PIN", key=f"rst_{p['id']}", type="primary"):
                    master_pin = st.session_state.admin_pin
                    admin_blob = p.get('admin_recovery_blob')
                    if not admin_blob:
                        st.error("Sem dados de recuperação.")
                    else:
                        target_plaintext = decrypt_string(admin_blob, master_pin)
                        if not target_plaintext:
                            st.error("PIN Admin inválido.")
                        else:
                            new_initial = generate_pin()
                            new_enc_target = encrypt_string(target_plaintext, new_initial)
                            if admin_reset_pin_db(p['id'], new_initial, new_enc_target):
                                st.success(f"Novo PIN: {new_initial}")
                                st.info("Envie este novo PIN para o usuário.")
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error("Erro no banco.")

        if st.button("Sair", type="secondary"):
            st.session_state.clear()
            st.rerun()

# --- PARTICIPANT VIEWS ---

def view_participant(p_id):
    p = get_participant(p_id)
    if not p:
        st.error("Link inválido ou não encontrado.")
        return

    # Header de Segurança
    st.markdown("""
    <div style='text-align: center; margin-bottom: 20px;'>
        <span style='background-color:#E8F5E9; color:#2E7D32; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; letter-spacing: 1px;'>🔒 AMBIENTE SEGURO</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.title(f"Olá, {p['name']}!")

    if 'user_auth' not in st.session_state: st.session_state.user_auth = False
    
    # TELA 1: LOGIN
    if not st.session_state.user_auth:
        st.markdown("<div class='standard-card'>", unsafe_allow_html=True)
        st.markdown("### Digite seu PIN")
        st.markdown("<p style='color:#666'>Use o PIN recebido para abrir seu envelope.</p>", unsafe_allow_html=True)

        pin_input = st.text_input("PIN", max_chars=6, type="password", key="login_pin", label_visibility="collapsed")
        
        if st.button("ABRIR ENVELOPE", type="primary"):
            if p['must_change_pin']:
                expected = p['pin_initial']
            else:
                expected = p['pin_final']

            if pin_input == expected:
                st.session_state.user_auth = True
                st.session_state.current_pin = pin_input
                st.rerun()
            else:
                st.error("PIN incorreto.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # TELA 2: TROCA OBRIGATÓRIA
    if p['must_change_pin']:
        st.markdown("<div class='standard-card' style='border-left: 5px solid #FFCA3A;'>", unsafe_allow_html=True)
        st.markdown("### ⚠️ Defina sua Senha Secreta")
        st.markdown("<p>Para garantir que ninguém (nem o Admin) veja quem você tirou, defina um novo PIN exclusivo.</p>", unsafe_allow_html=True)
        
        new_pin_1 = st.text_input("Novo PIN (6 números)", max_chars=6, type="password", key="np1")
        new_pin_2 = st.text_input("Confirme o PIN", max_chars=6, type="password", key="np2")
        
        if st.button("PROTEGER E ABRIR", type="primary"):
            if len(new_pin_1) != 6 or not new_pin_1.isdigit():
                st.error("O PIN deve ter 6 números.")
                return
            if new_pin_1 != new_pin_2:
                st.error("Os PINs não coincidem.")
                return
            if new_pin_1 == p['pin_initial']:
                st.error("Use um PIN diferente do inicial.")
                return
            
            target = decrypt_string(p['encrypted_target'], p['pin_initial'])
            if not target:
                st.error("Erro de criptografia.")
                return

            new_enc = encrypt_string(target, new_pin_1)
            
            if update_participant_pin(p['id'], new_pin_1, new_enc):
                st.session_state.current_pin = new_pin_1
                st.success("Senha definida!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Erro ao salvar.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # TELA 3: REVELAÇÃO
    reveal_at_iso = p.get('draws', {}).get('reveal_at')

    if reveal_at_iso:
        reveal_dt = datetime.fromisoformat(reveal_at_iso.replace('Z', '+00:00'))
        if datetime.now(reveal_dt.tzinfo) < reveal_dt:
             st.markdown(f"""
            <div class="custom-card" style="background-color: white; border: 2px solid #FFCA3A; color:#333;">
                <h3 style="color: #F59F00 !important;">⏳ Psiu! Ainda não...</h3>
                <p style="color: #666 !important;">A revelação será em:</p>
                <h2 style="color: #333 !important;">{reveal_dt.strftime('%d/%m/%Y %H:%M')}</h2>
            </div>
            """, unsafe_allow_html=True)
             return

    current_pin = st.session_state.current_pin
    target_name = decrypt_string(p['encrypted_target'], current_pin)

    if not target_name:
        st.error("Erro ao abrir envelope. Faça login novamente.")
        if st.button("Sair"):
            st.session_state.clear()
            st.rerun()
        return

    # EFEITO BALÕES
    st.balloons()

    # CARD PREMIUM DE REVELAÇÃO
    st.markdown(f"""
    <div class="reveal-card">
        <p class="reveal-title">SEU AMIGO SECRETO É</p>
        <div class="name-badge">{target_name}</div>
        <div class="shhh-box">
            <span>🤫</span> Guarde segredo!
        </div>
    </div>
    """, unsafe_allow_html=True)

    # CARD TROCA DE PIN (Discreto)
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("🔒 Trocar meu PIN"):
        st.caption("Use isso se achar que alguém descobriu sua senha.")
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
