import streamlit as st
import json
import base64
import hashlib
import time
import random
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ==========================================
# CONFIGURAÇÃO E DOCUMENTAÇÃO
# ==========================================
# Este app é uma versão Python/Streamlit do "Amigo Secreto Seguro".
#
# OBJETIVO: Uso recreativo (família/amigos).
# SEGURANÇA: Criptografia AES-256 (CBC) via PyCryptodome.
#            Chaves derivadas do PIN (6 dígitos) usando KDF estilo OpenSSL (MD5)
#            para compatibilidade com CryptoJS do front-end React.
# LIMITAÇÕES: 
#   - O PIN Admin padrão é '654321' (Beta).
#   - Não há banco de dados persistente (apenas st.session_state).
#   - A segurança depende da força dos PINs e da não interceptação dos links.

st.set_page_config(
    page_title="Amigo Secreto Seguro",
    page_icon="🎅",
    layout="centered"
)

# ==========================================
# BIBLIOTECA DE CRIPTOGRAFIA (COMPATÍVEL COM CRYPTOJS)
# ==========================================

def derive_key_and_iv(password: str, salt: bytes, key_length=32, iv_length=16):
    """
    Deriva Key e IV usando o método OpenSSL KDF (MD5 digest).
    Isso garante compatibilidade com CryptoJS.AES.encrypt() padrão.
    """
    d = d_i = b''
    pass_bytes = password.encode('utf-8')
    while len(d) < key_length + iv_length:
        d_i = hashlib.md5(d_i + pass_bytes + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt_payload(payload: dict, pin: str) -> str:
    """
    Criptografa um dicionário payload usando o PIN.
    Retorna string Base64 no formato OpenSSL (Salted__...).
    """
    try:
        json_str = json.dumps(payload)
        data_bytes = json_str.encode('utf-8')
        
        salt = get_random_bytes(8)
        key, iv = derive_key_and_iv(pin, salt)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        
        # Formato OpenSSL: "Salted__" + salt + ciphertext
        openssl_format = b"Salted__" + salt + ciphertext
        return base64.b64encode(openssl_format).decode('utf-8')
    except Exception as e:
        print(f"Erro na encriptação: {e}")
        return ""

def decrypt_payload(token: str, pin: str) -> dict:
    """
    Descriptografa o token Base64 usando o PIN.
    Suporta formato OpenSSL (gerado pelo React/CryptoJS).
    """
    try:
        encrypted_data = base64.b64decode(token)
        
        # Verifica cabeçalho "Salted__"
        if encrypted_data[:8] != b"Salted__":
            return None
            
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        key, iv = derive_key_and_iv(pin, salt)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        return None

# ==========================================
# LÓGICA DE SORTEIO E UTILITÁRIOS
# ==========================================

def clean_names(text):
    return [line.strip() for line in text.split('\n') if line.strip()]

def validate_names(names):
    duplicates = set([x for x in names if names.count(x) > 1])
    if duplicates:
        return False, f"Nomes duplicados: {', '.join(duplicates)}"
    if len(names) < 3:
        return False, "Mínimo de 3 participantes."
    return True, "OK"

def generate_pin():
    return f"{random.randint(0, 999999):06d}"

def shuffle_and_pair(names, reveal_at_ts, admin_pin):
    pool = names[:]
    max_attempts = 1000
    valid = False
    
    # Derangement (ninguém tira a si mesmo)
    for _ in range(max_attempts):
        random.shuffle(pool)
        if all(n != p for n, p in zip(names, pool)):
            valid = True
            break
            
    if not valid:
        return None

    draw_id = hex(int(time.time()))[2:]
    pairings = []
    
    for i, name in enumerate(names):
        pin = generate_pin()
        payload = {
            "ownerName": name,
            "receiverName": pool[i],
            "drawId": draw_id,
            "revealAt": reveal_at_ts, # Timestamp em ms ou None
            "salt": generate_pin() # Entropia extra
        }
        token = encrypt_payload(payload, pin)
        pairings.append({
            "ownerName": name,
            "pin": pin,
            "token": token
        })
        
    return {
        "drawId": draw_id,
        "createdAt": int(time.time() * 1000),
        "adminPin": admin_pin,
        "pairings": pairings,
        "revealAt": reveal_at_ts
    }

def format_date(ts_ms):
    if not ts_ms:
        return ""
    return datetime.fromtimestamp(ts_ms / 1000).strftime('%d/%m/%Y às %H:%M')

# ==========================================
# INTERFACE DO USUÁRIO
# ==========================================

def main():
    # CSS Customizado para estilo natalino/clean
    st.markdown("""
    <style>
    .stApp { background-color: #FFF8E1; color: #2C3E50; }
    h1, h2, h3 { color: #D42F2F !important; text-align: center; }
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; }
    .stTextArea textarea { border-radius: 8px; }
    .stTextInput input { border-radius: 8px; text-align: center; letter-spacing: 2px; }
    .copy-box { background: white; padding: 15px; border-radius: 8px; border: 1px solid #ddd; margin-bottom: 10px; }
    .footer { text-align: center; color: #aaa; font-size: 12px; margin-top: 50px; }
    </style>
    """, unsafe_allow_html=True)

    # Verifica parâmetros da URL
    query_params = st.query_params
    p_id = query_params.get("id", None)
    p_token = query_params.get("t", None)

    # ROTEAMENTO
    if p_id and p_token:
        view_participant(p_id, p_token)
    else:
        view_admin()
        
    st.markdown("""
    <div class='footer'>
        Amigo Secreto v0.3.0 (Streamlit) • Criptografia AES Client-Side Equivalent<br/>
        Não há armazenamento em banco de dados. Dados na sessão.
    </div>
    """, unsafe_allow_html=True)

def view_admin():
    # Inicializa estado da sessão
    if 'draw_data' not in st.session_state:
        st.session_state.draw_data = None
    if 'admin_authenticated' not in st.session_state:
        st.session_state.admin_authenticated = False

    # Tela 1: Configuração (se não houver sorteio gerado)
    if not st.session_state.draw_data:
        st.title("🎅 Configurar Sorteio")
        
        with st.container():
            st.markdown("**1. Participantes (um por linha)**")
            names_input = st.text_area("Lista de Nomes", height=150, placeholder="João\nMaria\nPedro", label_visibility="collapsed")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🧹 Limpar Lista"):
                    cleaned = clean_names(names_input)
                    st.session_state.temp_names = "\n".join(cleaned)
                    st.rerun() # Refresh para atualizar o campo (se suportado pelo binding)
            with col2:
                if st.button("✅ Validar"):
                    cleaned = clean_names(names_input)
                    valid, msg = validate_names(cleaned)
                    if valid:
                        st.success(f"Lista válida com {len(cleaned)} nomes!")
                    else:
                        st.error(msg)

            st.markdown("---")
            st.markdown("**2. Data da Revelação (Opcional)**")
            reveal_date = st.date_input("Data", value=None)
            reveal_time = st.time_input("Hora", value=None)
            
            st.markdown("---")
            st.markdown("**3. PIN Mestre do Organizador**")
            st.info("Nesta versão beta, o PIN padrão é **654321** para testes.")
            admin_pin = st.text_input("PIN Admin", value="654321", max_chars=6, type="password")

            if st.button("🎲 Gerar Sorteio", type="primary"):
                cleaned = clean_names(names_input)
                valid, msg = validate_names(cleaned)
                
                if not valid:
                    st.error(msg)
                    return
                
                if len(admin_pin) != 6:
                    st.error("PIN Admin deve ter 6 dígitos.")
                    return

                ts_ms = None
                if reveal_date and reveal_time:
                    dt = datetime.combine(reveal_date, reveal_time)
                    ts_ms = int(dt.timestamp() * 1000)

                draw_result = shuffle_and_pair(cleaned, ts_ms, admin_pin)
                if draw_result:
                    st.session_state.draw_data = draw_result
                    st.session_state.admin_authenticated = True
                    st.rerun()
                else:
                    st.error("Erro ao realizar sorteio (falha no embaralhamento). Tente novamente.")

    # Tela 2: Login Admin (se houver sorteio mas não autenticado)
    elif not st.session_state.admin_authenticated:
        st.title("🛡️ Acesso do Organizador")
        st.markdown("Um sorteio está ativo nesta sessão.")
        
        pin_attempt = st.text_input("Digite o PIN Mestre", max_chars=6, type="password")
        
        if st.button("Acessar Painel"):
            if pin_attempt == st.session_state.draw_data["adminPin"]:
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("PIN Incorreto.")
        
        st.markdown("---")
        if st.button("🗑️ Encerrar Sorteio (Resetar)"):
             st.session_state.clear()
             st.rerun()

    # Tela 3: Dashboard Admin (autenticado)
    else:
        data = st.session_state.draw_data
        st.title("📋 Painel de Envio")
        st.caption(f"Sorteio ID: {data['drawId']}")
        
        base_url = "https://sorteioapp-2025.streamlit.app"
        
        # Gera texto de backup
        backup_text = f"BACKUP AMIGO SECRETO [{data['drawId']}]\n"
        if data['revealAt']:
            backup_text += f"Revelação: {format_date(data['revealAt'])}\n"
        backup_text += "\n"

        for p in data['pairings']:
            name = p['ownerName']
            pin = p['pin']
            token = p['token']
            link = f"{base_url}/?id={name}&t={token}" # Encode URI component seria ideal aqui, mas simplificado
            
            msg = f"🎄 *AMIGO SECRETO* 🎄\n\nOlá {name}! 🎅\nAqui está seu envelope secreto.\n\n🔗 *Link:* {link}\n🔑 *Sua Senha:* {pin}"
            if data['revealAt']:
                msg += f"\n📅 *Revelação:* {format_date(data['revealAt'])}"
            msg += "\n\n_Não compartilhe este link ou senha!_"
            
            backup_text += f"{name} | PIN: {pin} | Link: {link}\n"

            with st.expander(f"✉️ {name}", expanded=False):
                st.code(msg, language=None)
                st.caption("Copie o texto acima e envie no WhatsApp.")

        st.markdown("---")
        st.download_button("💾 Baixar Backup (.txt)", backup_text, file_name=f"backup-{data['drawId']}.txt")
        
        if st.button("🗑️ Encerrar Sorteio", type="primary"):
            st.session_state.clear()
            st.query_params.clear()
            st.rerun()

def view_participant(p_id, p_token):
    st.title("💌 Envelope Seguro")
    
    # Rate Limiting Logic
    if 'strikes' not in st.session_state:
        st.session_state.strikes = 0
    if 'blocked_until' not in st.session_state:
        st.session_state.blocked_until = 0

    if time.time() < st.session_state.blocked_until:
        wait_s = int(st.session_state.blocked_until - time.time())
        st.error(f"Muitas tentativas. Aguarde {wait_s} segundos.")
        return

    st.markdown(f"Olá, **{p_id}**! Este envelope é seu.")
    
    pin = st.text_input("Digite seu PIN de 6 dígitos", max_chars=6, type="password", key="user_pin")
    
    if st.button("Abrir Envelope", type="primary"):
        if len(pin) != 6:
            st.warning("O PIN deve ter 6 dígitos.")
            return
            
        payload = decrypt_payload(p_token, pin)
        
        if not payload:
            st.session_state.strikes += 1
            if st.session_state.strikes >= 3:
                st.session_state.blocked_until = time.time() + 30
                st.error("PIN incorreto. Bloqueado por 30s.")
            else:
                st.error("PIN incorreto. Tente novamente.")
            return
        
        # Reset strikes on success
        st.session_state.strikes = 0
        
        # Validation Integrity
        if payload.get('ownerName') != p_id:
            st.error("Link corrompido ou inválido para este usuário.")
            return
            
        # Check Reveal Date
        reveal_at = payload.get('revealAt')
        if reveal_at and (time.time() * 1000) < reveal_at:
            st.warning("⏳ Psiu! Ainda não...")
            st.info(f"A revelação será em: {format_date(reveal_at)}")
            return
            
        # Success Reveal
        receiver = payload.get('receiverName')
        st.balloons()
        st.success("🎉 Envelope Aberto!")
        
        st.markdown("### Você tirou:")
        st.markdown(f"<div style='background:#D42F2F;color:white;padding:20px;border-radius:10px;text-align:center;font-size:24px;font-weight:bold;'>{receiver}</div>", unsafe_allow_html=True)
        st.markdown("")
        st.markdown("🤫 *Shhh! Guarde segredo.*")
        
        search_url = f"https://www.google.com/search?q=ideias+de+presente+para+{receiver}"
        st.markdown(f"[🎁 Buscar ideias de presente no Google]({search_url})")

if __name__ == "__main__":
    main()
