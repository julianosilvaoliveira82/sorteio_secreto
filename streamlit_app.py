import streamlit as st
import json
import base64
import hashlib
import time
import random
import urllib.parse
import re
import pytz
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from supabase import create_client, Client

# ==========================================
# CONFIGURAÇÃO E DOCUMENTAÇÃO
# ==========================================
st.set_page_config(
    page_title="Amigo Secreto Seguro",
    page_icon="🎅",
    layout="centered"
)

# TIMEZONE SETUP
BR_TZ = pytz.timezone('America/Sao_Paulo')

# ==========================================
# SUPABASE INTEGRATION
# ==========================================

@st.cache_resource
def get_supabase_client() -> Client:
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["anon_key"]
        return create_client(url, key)
    except Exception as e:
        st.error(f"Erro ao configurar Supabase: {e}")
        return None

supabase = get_supabase_client()

# --- DB FUNCTIONS ---

def hash_pin(pin: str) -> str:
    """Gera hash SHA-256 do PIN para armazenamento seguro."""
    return hashlib.sha256(pin.encode('utf-8')).hexdigest()

def create_draw_in_db(admin_pin: str, reveal_at_dt: datetime, pairs: list) -> str:
    if not supabase: return None

    try:
        # 1. Create Draw (Store Hashed PIN)
        draw_data = {
            "admin_pin_hash": hash_pin(admin_pin),
            "reveal_at": reveal_at_dt.isoformat() if reveal_at_dt else None
        }
        res_draw = supabase.table("draws").insert(draw_data).execute()
        if not res_draw.data: return None
        draw_id = res_draw.data[0]['id']
        
        # 2. Create Participants
        participants_data = []
        for p in pairs:
            enc_target = encrypt_string(p['receiverName'], p['pin'])
            admin_blob = encrypt_string(p['receiverName'], admin_pin)

            participants_data.append({
                "draw_id": draw_id,
                "name": p['ownerName'],
                "encrypted_target": enc_target,
                "admin_recovery_blob": admin_blob,
                "pin_initial_hash": hash_pin(p['pin']),
                "pin_final_hash": None,
                "must_change_pin": True,
                "failed_attempts": 0
            })

        supabase.table("participants").insert(participants_data).execute()
        return draw_id
    except Exception as e:
        st.error(f"Erro ao criar sorteio no banco: {e}")
        return None

def load_draw(draw_id: str, admin_pin: str):
    if not supabase: return None, "Erro de conexão."
    try:
        res = supabase.table("draws").select("*").eq("id", draw_id).execute()
        if not res.data: return None, "Sorteio não encontrado."
        draw = res.data[0]
        
        # Validate Hash
        if draw['admin_pin_hash'] != hash_pin(admin_pin):
            return None, "PIN incorreto."
            
        return draw, None
    except Exception as e:
        return None, f"Erro: {str(e)}"

def get_draw_participants(draw_id: str):
    if not supabase: return []
    try:
        res = supabase.table("participants").select("*").eq("draw_id", draw_id).order("name").execute()
        return res.data
    except Exception as e:
        st.error(f"Erro ao buscar participantes: {e}")
        return []

def get_participant(p_id: str):
    if not supabase: return None
    try:
        res = supabase.table("participants").select("*, draws(reveal_at)").eq("id", p_id).execute()
        if res.data: return res.data[0]
        return None
    except Exception as e:
        return None

def update_participant_pin(p_id: str, new_pin: str, new_encrypted_target: str):
    if not supabase: return False
    try:
        data = {
            "pin_final_hash": hash_pin(new_pin),
            "encrypted_target": new_encrypted_target,
            "must_change_pin": False,
            "last_activity_at": datetime.now(BR_TZ).isoformat()
        }
        supabase.table("participants").update(data).eq("id", p_id).execute()
        return True
    except Exception as e:
        st.error(f"Erro ao atualizar PIN: {e}")
        return False

def admin_reset_pin_db(p_id: str, new_initial_pin: str, new_encrypted_target: str):
    if not supabase: return False
    try:
        data = {
            "pin_initial_hash": hash_pin(new_initial_pin),
            "pin_final_hash": None,
            "must_change_pin": True,
            "encrypted_target": new_encrypted_target,
            "failed_attempts": 0,
            "locked_until": None,
            "last_activity_at": datetime.now(BR_TZ).isoformat()
        }
        supabase.table("participants").update(data).eq("id", p_id).execute()
        return True
    except Exception as e:
        st.error(f"Erro ao resetar PIN: {e}")
        return False

def register_failed_attempt(p_id: str, current_fails: int):
    if not supabase: return
    new_fails = current_fails + 1
    update_data = {"failed_attempts": new_fails, "last_activity_at": datetime.now(BR_TZ).isoformat()}

    lock_duration = 0
    if new_fails >= 10:
        lock_duration = 15
    elif new_fails >= 5:
        lock_duration = 5
        
    if lock_duration > 0:
        unlock_time = datetime.now(BR_TZ).timestamp() + (lock_duration * 60)
        update_data["locked_until"] = datetime.fromtimestamp(unlock_time, BR_TZ).isoformat()

    try:
        supabase.table("participants").update(update_data).eq("id", p_id).execute()
        return lock_duration
    except Exception as e:
        print(f"Error logging fail: {e}")
        return 0

def register_success(p_id: str, is_first_open: bool):
    if not supabase: return
    update_data = {
        "failed_attempts": 0,
        "locked_until": None,
        "last_activity_at": datetime.now(BR_TZ).isoformat()
    }
    if is_first_open:
        update_data["opened_at"] = datetime.now(BR_TZ).isoformat()
    try:
        supabase.table("participants").update(update_data).eq("id", p_id).execute()
    except Exception as e:
        print(f"Error logging success: {e}")

# ==========================================
# CRIPTOGRAFIA & LÓGICA
# ==========================================

SALT_FIXO = b"AMIGO_SECRETO_SALT_2025"
ITERATIONS = 10000
KEY_SIZE = 32

def get_key(pin: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), SALT_FIXO, ITERATIONS, dklen=KEY_SIZE)

def encrypt_string(plaintext: str, pin: str) -> str:
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
    except Exception:
        return ""

def decrypt_string(token: str, pin: str) -> str:
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
    except Exception:
        return None

def clean_names(text):
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        normalized = re.sub(r'\s+', ' ', line).strip()
        if normalized:
            cleaned.append(normalized.title())
    return cleaned

def validate_names(names):
    if len(names) < 3: return False, "Mínimo de 3 participantes."
    names_lower = [n.lower() for n in names]
    duplicates = set([x for x in names if names_lower.count(x.lower()) > 1])
    if duplicates: return False, f"Nomes duplicados: {', '.join(duplicates)}"
    return True, "OK"

def generate_pin():
    return f"{random.randint(0, 999999):06d}"

def generate_single_cycle(names):
    """
    Gera um sorteio de ciclo único (A->B->C->A).
    Garante que todos são sorteados e ninguém se tira.
    """
    if len(names) < 2: return None
    pool = names[:]
    random.shuffle(pool)
    
    pairs = []
    n = len(pool)
    for i in range(n):
        giver = pool[i]
        receiver = pool[(i + 1) % n] # Wraps around
        pairs.append({'ownerName': giver, 'receiverName': receiver})
    return pairs

# ==========================================
# UI
# ==========================================

def inject_css():
    st.markdown("""
    <style>
    :root { --bg-color: #F8F5E5; --card-color: #1E1E24; --text-color: #333333; --accent-color: #E63946; --highlight-color: #1E90FF; }
    .stApp { background-color: var(--bg-color); color: #333; font-family: 'Segoe UI', sans-serif; }
    h1, h2, h3 { color: var(--accent-color) !important; font-weight: 700; text-align: center; }
    div[data-testid="stDataFrame"] { width: 100%; }

    .reveal-card { background-color: var(--card-color); color: #FFF; padding: 40px; border-radius: 16px; text-align: center; margin: 20px 0; }
    .name-badge { background-color: var(--highlight-color); color: white; font-size: 28px; font-weight: 800; padding: 15px 30px; border-radius: 50px; margin: 10px 0; display: inline-block; }

    .standard-card { background-color: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); margin-bottom: 20px; border: 1px solid #EAEAEA; }

    .wait-card { background-color: #FFF3CD; border: 2px solid #FFEEBA; color: #333; padding: 30px; border-radius: 12px; text-align: center; margin-top: 20px; }
    .wait-title { color: #856404 !important; font-weight: 800; margin: 0; }

    /* Login Card Style (Applied to st.container with border=True) */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #FFFFFF !important;
        border: 1px solid #EEE !important;
        border-radius: 12px !important;
        padding: 24px !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05) !important;
    }

    /* Fix for button alignment inside cards */
    .stButton { width: 100%; }
    </style>
    """, unsafe_allow_html=True)

def main():
    inject_css()
    query_params = st.query_params
    p_id = query_params.get("id", None)
    if p_id: view_participant(p_id)
    else: view_admin()

    st.markdown("<div style='text-align:center;color:#AAA;font-size:12px;margin-top:50px;'>Amigo Secreto v1.0.1 • Secure Hash • Single Cycle</div>", unsafe_allow_html=True)

# --- ADMIN ---

def view_admin():
    if 'admin_logged' not in st.session_state: st.session_state.admin_logged = False
    if 'current_draw_id' not in st.session_state: st.session_state.current_draw_id = None
    if 'admin_pin' not in st.session_state: st.session_state.admin_pin = "654321"

    if not st.session_state.admin_logged:
        st.title("🛡️ Acesso Restrito")
        # Centering Login
        cols = st.columns([1, 2, 1])
        with cols[1]:
            with st.container(border=True):
                st.markdown("<p style='text-align:center'>Digite o PIN de Administrador.</p>", unsafe_allow_html=True)
                pin = st.text_input("PIN Admin", type="password", max_chars=6)
                if st.button("ENTRAR", type="primary"):
                    if pin == "654321":
                        st.session_state.admin_logged = True
                        st.rerun()
                    else:
                        st.error("PIN incorreto.")
        return

    if not st.session_state.current_draw_id:
        st.title("🎅 Configurar Sorteio")
        with st.container():
            with st.form("config_draw"):
                st.markdown("Preencha os dados abaixo para gerar um novo sorteio.")
                names_input = st.text_area("Participantes (um por linha)", height=150, placeholder="João\nMaria\nPedro")
                col1, col2 = st.columns(2)
                with col1: reveal_date = st.date_input("Dia Revelação", value=None, format="DD/MM/YYYY")
                with col2: reveal_time = st.time_input("Hora Revelação", value=None)
                
                admin_pin_input = st.text_input("PIN Admin (Padrão 654321)", value="654321", max_chars=6, type="password")
                
                submitted = st.form_submit_button("🎲 GERAR SORTEIO", type="primary")

                if submitted:
                    names = clean_names(names_input)
                    valid, msg = validate_names(names)
                    if not valid:
                        st.error(msg)
                    else:
                        pairs_list = generate_single_cycle(names)
                        if not pairs_list:
                            st.error("Erro ao gerar combinação.")
                        else:
                            # Assign PINs
                            for p in pairs_list:
                                p['pin'] = generate_pin()

                            ts_dt = None
                            if reveal_date and reveal_time:
                                local_dt = datetime.combine(reveal_date, reveal_time)
                                ts_dt = BR_TZ.localize(local_dt)

                            with st.spinner("Criando..."):
                                draw_id = create_draw_in_db(admin_pin_input, ts_dt, pairs_list)
                                if draw_id:
                                    st.session_state.current_draw_id = draw_id
                                    st.session_state.admin_pin = admin_pin_input
                                    st.rerun()
                                else:
                                    st.error("Erro ao salvar.")

        st.markdown("---")
        with st.expander("📂 Carregar Sorteio"):
            did = st.text_input("ID do Sorteio")
            dpin = st.text_input("PIN Admin", type="password")
            if st.button("Carregar", type="secondary"):
                if did and len(dpin) == 6:
                    draw, error = load_draw(did, dpin)
                    if draw:
                        st.session_state.current_draw_id = draw['id']
                        st.session_state.admin_pin = dpin
                        st.success("Carregado!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(error)

    else:
        draw_id = st.session_state.current_draw_id
        st.title("📋 Painel Admin")
        st.caption(f"ID: {draw_id}")
        
        participants = get_draw_participants(draw_id)
        
        if participants:
            st.subheader("Status dos Participantes")
            status_data = []
            for p in participants:
                pin_status = "Privado ✅" if not p['must_change_pin'] else "Inicial ⚠️"
                opened = "Sim 🎉" if p['opened_at'] else "Não"
                locked = "BLOQUEADO ⛔" if p['locked_until'] and datetime.fromisoformat(p['locked_until']) > datetime.now(BR_TZ) else "Ativo"

                status_data.append({
                    "Nome": p['name'],
                    "PIN": pin_status,
                    "Abriu?": opened,
                    "Estado": locked,
                    "Erros": p['failed_attempts']
                })
            st.dataframe(status_data, hide_index=True)

        if not participants:
            st.error("Erro ao buscar dados.")
        else:
            for p in participants:
                with st.expander(f"👤 {p['name']}", expanded=False):
                    link = f"https://sorteioapp-2025.streamlit.app/?id={p['id']}"
                    st.text_input("Link", value=link, key=f"lk_{p['id']}")

                    if st.button("🔄 Resetar PIN", key=f"rst_{p['id']}", type="primary"):
                        master_pin = st.session_state.admin_pin
                        admin_blob = p.get('admin_recovery_blob')
                        if admin_blob:
                            target = decrypt_string(admin_blob, master_pin)
                            if target:
                                new_initial = generate_pin()
                                new_enc = encrypt_string(target, new_initial)
                                if admin_reset_pin_db(p['id'], new_initial, new_enc):
                                    st.success(f"Novo PIN: {new_initial}")
                                    time.sleep(5)
                                else:
                                    st.error("Erro DB")
                            else:
                                st.error("Erro Decrypt Admin")
                        else:
                            st.error("Sem blob recovery")

        if st.button("Sair", type="secondary"):
            st.session_state.clear()
            st.rerun()

# --- PARTICIPANT ---

def view_participant(p_id):
    p = get_participant(p_id)
    if not p:
        st.error("Link inválido.")
        return

    st.markdown("""
    <div style='text-align: center; margin-bottom: 20px;'>
        <span style='background-color:#E8F5E9; color:#2E7D32; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; letter-spacing: 1px;'>🔒 AMBIENTE SEGURO</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.title(f"Olá, {p['name']}!")

    if p.get('locked_until'):
        lock_dt = datetime.fromisoformat(p['locked_until'])
        if lock_dt > datetime.now(BR_TZ):
            wait_min = int((lock_dt - datetime.now(BR_TZ)).total_seconds() / 60) + 1
            st.error(f"⛔ Bloqueado. Tente novamente em {wait_min} minutos.")
            return

    if 'user_auth' not in st.session_state: st.session_state.user_auth = False

    # TELA 1: LOGIN (Refactored for Clean Card)
    if not st.session_state.user_auth:
        cols = st.columns([1, 2, 1])
        with cols[1]:
            # Container with border=True acts as the visual card
            with st.container(border=True):
                st.markdown("<h3 style='text-align:center;'>Digite seu PIN</h3>", unsafe_allow_html=True)
                st.markdown("<p style='text-align:center; color:#666;'>Use o PIN recebido para abrir seu envelope.</p>", unsafe_allow_html=True)

                pin_input = st.text_input("PIN", max_chars=6, type="password", key="login_pin", label_visibility="collapsed", placeholder="••••••")

                if st.button("ABRIR ENVELOPE", type="primary"):
                    # Check Hash
                    input_hash = hash_pin(pin_input)
                    expected_hash = p['pin_initial_hash'] if p['must_change_pin'] else p['pin_final_hash']

                    if input_hash == expected_hash:
                        st.session_state.user_auth = True
                        st.session_state.current_pin = pin_input
                        is_first = p['opened_at'] is None
                        register_success(p['id'], is_first)
                        st.rerun()
                    else:
                        duration = register_failed_attempt(p['id'], p['failed_attempts'] or 0)
                        if duration > 0:
                            st.error(f"PIN incorreto. Bloqueado por {duration} minutos.")
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error("PIN incorreto.")
        return

    # TELA 2: TROCA OBRIGATÓRIA
    if p['must_change_pin']:
        cols = st.columns([1, 2, 1])
        with cols[1]:
            with st.container(border=True):
                st.markdown("<h3 style='text-align:center;'>⚠️ Defina sua Senha</h3>", unsafe_allow_html=True)
                st.markdown("<p style='text-align:center;'>Crie um PIN secreto que só você sabe.</p>", unsafe_allow_html=True)
                new_pin_1 = st.text_input("Novo PIN", max_chars=6, type="password", key="np1")
                new_pin_2 = st.text_input("Confirme", max_chars=6, type="password", key="np2")

                if st.button("SALVAR E ABRIR", type="primary"):
                    if len(new_pin_1) == 6 and new_pin_1.isdigit() and new_pin_1 == new_pin_2:
                        if hash_pin(new_pin_1) == p['pin_initial_hash']:
                            st.error("Use um PIN diferente do inicial.")
                        else:
                            target = decrypt_string(p['encrypted_target'], st.session_state.current_pin)
                            if target:
                                new_enc = encrypt_string(target, new_pin_1)
                                if update_participant_pin(p['id'], new_pin_1, new_enc):
                                    st.session_state.current_pin = new_pin_1
                                    st.success("Senha definida!")
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("Erro ao salvar.")
                            else:
                                st.error("Erro fatal criptografia.")
                    else:
                        st.error("PIN inválido ou não conferem.")
        return

    reveal_at_iso = p.get('draws', {}).get('reveal_at')
    if reveal_at_iso:
        reveal_dt = datetime.fromisoformat(reveal_at_iso)
        now_br = datetime.now(BR_TZ)
        if reveal_dt > now_br:
             fmt_date = reveal_dt.astimezone(BR_TZ).strftime('%d/%m/%Y %H:%M')
             st.markdown(f"""
            <div class="wait-card">
                <h3 class="wait-title">⏳ Psiu! Ainda não...</h3>
                <p>A revelação será em:</p>
                <div style="font-size:24px;font-weight:bold;">{fmt_date}</div>
            </div>
            """, unsafe_allow_html=True)
             return

    target = decrypt_string(p['encrypted_target'], st.session_state.current_pin)
    if not target:
        st.error("Erro ao decriptar.")
        return

    st.balloons()
    st.markdown(f"""
    <div class="reveal-card">
        <p class="reveal-title">VOCÊ TIROU</p>
        <div class="name-badge">{target}</div>
        <div class="shhh-box">🤫 Segredo!</div>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
