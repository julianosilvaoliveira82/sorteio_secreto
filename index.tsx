/*
 * AMIGO SECRETO SEGURO (Client-side AES) - v0.4.0
 * 
 * AVISO DE SEGURANÇA E LIMITAÇÕES:
 * 1. Uso Recreativo: Este app foi projetado para grupos de família e amigos.
 * 2. Criptografia: Utilizamos AES-256 (via CryptoJS). O link contém os dados criptografados.
 *    A segurança depende da força do PIN (6 dígitos) e da não interceptação do link.
 * 3. PIN Admin: Para facilitar testes nesta versão beta, o PIN padrão é '654321'.
 * 4. Persistência: Não há banco de dados. O estado do sorteio fica no localStorage do Admin
 *    e no token URL de cada participante.
 */

import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

// Declaração de tipos para evitar 'any' excessivo no CryptoJS
interface CipherParams {
  toString: (encoder?: any) => string;
  ciphertext: { toString: (encoder: any) => string };
  iv: { toString: (encoder: any) => string };
}
interface AESStatic {
  encrypt: (message: string, key: any, cfg?: any) => CipherParams;
  decrypt: (ciphertext: any, key: any, cfg?: any) => { toString: (encoder: any) => string };
}
interface LibWordArray {
  toString: (encoder?: any) => string;
}
interface EncHex {
  parse: (str: string) => LibWordArray;
}
interface EncBase64 {
  parse: (str: string) => LibWordArray;
  stringify: (wordArray: LibWordArray) => string;
}
interface EncUtf8 {
  parse: (str: string) => LibWordArray;
}
interface PBKDF2Static {
    (password: string, salt: LibWordArray, cfg: any): LibWordArray;
}
interface CryptoStatic {
  AES: AESStatic;
  enc: {
      Utf8: any;
      Base64: EncBase64;
      Hex: EncHex;
  };
  lib: {
      WordArray: { random: (n: number) => LibWordArray };
  };
  PBKDF2: PBKDF2Static;
  algo: { SHA256: any };
  mode: { CBC: any };
  pad: { Pkcs7: any };
}
// Injetado via CDN no index.html
declare const CryptoJS: CryptoStatic;

// --- 1. TYPES ---

type Participant = {
  name: string;
};

type EncryptedToken = string;

// Payload que fica dentro do envelope criptografado
type SecurePayload = {
  ownerName: string;     // Quem abre o envelope
  receiverName: string;  // Quem foi tirado
  drawId: string;        // ID do sorteio para validação
  revealAt: number | null; // Timestamp da revelação (null = imediato)
  salt: string;          // Entropia extra
};

// Estado salvo no localStorage do Admin
type StoredDraw = {
  drawId: string;
  createdAt: number;
  revealAt: number | null; // null se não definido
  adminPin: string;      // PIN Mestre do Admin
  participants: Participant[];
  pairings: Array<{
    ownerName: string;
    pin: string;
    token: EncryptedToken;
  }>;
};

// --- 2. LIB (CRYPTO, LOGIC, STORAGE) ---

const SALT_FIXO_STR = "AMIGO_SECRETO_SALT_2025";

const Lib = {
  // Gera PIN numérico de 6 dígitos para o participante
  generatePin: (): string => {
    return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
  },

  // Gera ID aleatório curto
  generateId: (): string => {
    return Math.random().toString(36).substring(2, 10);
  },

  // Limpa entrada de nomes (remove vazios e trim)
  cleanNames: (input: string): string[] => {
    return input
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0);
  },

  // Valida duplicatas e quantidade mínima
  validateNames: (names: string[]): { valid: boolean; duplicates: string[] } => {
    // Case insensitive check para melhor UX
    const lowerNames = names.map(n => n.toLowerCase());
    const duplicates: string[] = [];
    
    names.forEach((name, index) => {
      if (lowerNames.indexOf(name.toLowerCase()) !== index && !duplicates.includes(name)) {
        duplicates.push(name);
      }
    });

    return {
      valid: duplicates.length === 0 && names.length >= 3,
      duplicates
    };
  },

  // Deriva chave consistente com o backend Python
  getKey: (pin: string): LibWordArray => {
      const salt = CryptoJS.enc.Utf8.parse(SALT_FIXO_STR);
      return CryptoJS.PBKDF2(pin, salt, {
          keySize: 256/32,
          iterations: 10000,
          hasher: CryptoJS.algo.SHA256
      });
  },

  // Criptografa objeto payload usando PIN como chave
  encryptPayload: (payload: SecurePayload, pin: string): string => {
    try {
        const key = Lib.getKey(pin);
        const iv = CryptoJS.lib.WordArray.random(16);
        const jsonStr = JSON.stringify(payload);

        const encrypted = CryptoJS.AES.encrypt(jsonStr, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        const tokenData = {
            iv: CryptoJS.enc.Base64.stringify(iv),
            ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext)
        };

        const jsonToken = JSON.stringify(tokenData);
        // URL Safe Base64
        return btoa(jsonToken).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (e) {
        console.error(e);
        return "";
    }
  },

  // Tenta descriptografar token. Retorna null se PIN errado ou corrompido.
  decryptPayload: (token: string, pin: string): SecurePayload | null => {
    try {
      // Decode URL Safe Base64
      let base64 = token.replace(/-/g, '+').replace(/_/g, '/');
      const padLen = (4 - (base64.length % 4)) % 4;
      base64 += "=".repeat(padLen);

      const jsonToken = atob(base64);
      const tokenData = JSON.parse(jsonToken);

      const iv = CryptoJS.enc.Base64.parse(tokenData.iv);
      const ciphertext = CryptoJS.enc.Base64.parse(tokenData.ciphertext);
      const key = Lib.getKey(pin);

      const decrypted = CryptoJS.AES.decrypt(
          { ciphertext: ciphertext } as any,
          key,
          {
              iv: iv,
              mode: CryptoJS.mode.CBC,
              padding: CryptoJS.pad.Pkcs7
          }
      );

      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
      if (!decryptedString) return null;
      return JSON.parse(decryptedString);
    } catch (e) {
      console.error(e);
      return null;
    }
  },

  // Algoritmo Fisher-Yates com verificação de Derangement (ninguém se tira)
  shuffleAndPair: (names: string[], revealAt: number | null, adminPin: string): StoredDraw | null => {
    const n = names.length;
    if (n < 3) return null;

    let pool = [...names];
    let isValid = false;
    let attempts = 0;
    const MAX_ATTEMPTS = 1000;

    while (!isValid && attempts < MAX_ATTEMPTS) {
      attempts++;
      // Embaralha
      for (let i = pool.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [pool[i], pool[j]] = [pool[j], pool[i]];
      }

      // Verifica se alguém tirou a si mesmo
      isValid = true;
      for (let i = 0; i < n; i++) {
        if (names[i] === pool[i]) {
          isValid = false;
          break;
        }
      }
    }

    if (!isValid) return null;

    const drawId = Lib.generateId();
    const pairings = names.map((name, i) => {
      const pin = Lib.generatePin();
      const payload: SecurePayload = {
        ownerName: name,
        receiverName: pool[i],
        drawId: drawId,
        revealAt: revealAt,
        salt: Lib.generateId()
      };
      return {
        ownerName: name,
        pin: pin,
        token: Lib.encryptPayload(payload, pin)
      };
    });

    return {
      drawId,
      createdAt: Date.now(),
      revealAt,
      adminPin,
      participants: names.map(n => ({ name: n })),
      pairings
    };
  },

  // Formata data amigável
  formatDate: (timestamp: number) => {
    return new Date(timestamp).toLocaleString('pt-BR', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
    });
  }
};

const STORAGE_KEY = 'amigo_secreto_v4_backup';

// --- 3. COMPONENTS ---

// Tela de Configuração (Admin Setup)
const AdminSetup = ({ onGenerate, onRestore }: { 
  onGenerate: (names: string[], date: number | null, adminPin: string) => void,
  onRestore: (data: StoredDraw) => void 
}) => {
  const [input, setInput] = useState('');
  const [dateVal, setDateVal] = useState('');
  const [adminPin, setAdminPin] = useState('654321'); // Default explícito conforme requisito
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [backup, setBackup] = useState<StoredDraw | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        setBackup(JSON.parse(saved));
      } catch (e) { localStorage.removeItem(STORAGE_KEY); }
    }
  }, []);

  const handleClean = () => {
    const cleaned = Lib.cleanNames(input);
    setInput(cleaned.join('\n'));
    setSuccessMsg('Lista limpa (espaços e linhas vazias removidos).');
    setError('');
  };

  const handleResetForm = () => {
    if (input || dateVal || adminPin !== '654321') {
       if (!confirm('Deseja limpar todos os campos e voltar ao padrão?')) return;
    }
    setInput('');
    setDateVal('');
    setAdminPin('654321');
    setError('');
    setSuccessMsg('');
  };

  const handleValidate = () => {
    const names = Lib.cleanNames(input);
    const result = Lib.validateNames(names);
    
    if (result.duplicates.length > 0) {
      setError(`Nomes duplicados: ${result.duplicates.join(', ')}. Use apelidos (ex: João A, João B).`);
      setSuccessMsg('');
    } else if (names.length < 3) {
      setError(`Mínimo de 3 participantes (atual: ${names.length}).`);
      setSuccessMsg('');
    } else {
      setSuccessMsg(`Lista válida com ${names.length} participantes! Pronto para sortear.`);
      setError('');
    }
  };

  const handleGenerate = () => {
    const names = Lib.cleanNames(input);
    const validation = Lib.validateNames(names);

    if (!validation.valid) {
      handleValidate();
      return;
    }

    if (adminPin.length !== 6) {
      setError('Defina um PIN de Admin com 6 dígitos.');
      setSuccessMsg('');
      return;
    }

    // Se dateVal estiver vazio, passamos null (sem trava de data)
    let timestamp: number | null = null;
    if (dateVal) {
      timestamp = new Date(dateVal).getTime();
    }

    onGenerate(names, timestamp, adminPin);
  };

  return (
    <div className="card fade-in">
      <div className="header-icon">🎅⚙️</div>
      <h2>Configurar Sorteio</h2>
      
      {backup && (
        <div className="alert alert-info">
          <span>Sorteio existente de {Lib.formatDate(backup.createdAt)}</span>
          <div style={{marginTop: '8px', display: 'flex', gap: '8px'}}>
             <button className="btn-sm btn-secondary" onClick={() => onRestore(backup)}>Retomar</button>
             <button className="btn-sm btn-outline" onClick={() => { localStorage.removeItem(STORAGE_KEY); setBackup(null); }}>Descartar</button>
          </div>
        </div>
      )}

      <label className="label">1. Participantes (um por linha)</label>
      <textarea
        className="input-area"
        value={input}
        onChange={e => setInput(e.target.value)}
        placeholder="João Silva&#10;Maria Souza&#10;Pedro Santos"
      />

      <div className="actions-row">
        <button className="btn-sm btn-outline" onClick={handleClean}>🧹 Limpar Lista</button>
        <button className="btn-sm btn-outline" onClick={handleResetForm}>🔄 Resetar</button>
        <button className="btn-sm btn-outline" onClick={handleValidate}>✅ Validar</button>
      </div>

      <label className="label" style={{marginTop: '16px'}}>2. Data da Revelação (Opcional)</label>
      <p className="text-sm text-gray" style={{marginBottom: '5px'}}>Se deixar em branco, a revelação é imediata.</p>
      <input 
        type="datetime-local" 
        className="input-field"
        value={dateVal}
        onChange={e => setDateVal(e.target.value)}
      />

      <label className="label" style={{marginTop: '16px'}}>3. PIN Mestre do Organizador</label>
      <p className="text-sm text-gray" style={{marginBottom: '5px'}}>
        Usado para acessar o painel de envio novamente.
      </p>
      <input 
        type="tel" 
        className="input-field"
        style={{ letterSpacing: '4px', fontWeight: 'bold' }}
        maxLength={6}
        inputMode="numeric"
        placeholder="000000"
        value={adminPin}
        onChange={e => setAdminPin(e.target.value.replace(/\D/g, ''))}
      />

      {error && <div className="alert alert-error">{error}</div>}
      {successMsg && <div className="alert alert-success">{successMsg}</div>}

      <button className="btn btn-primary" style={{marginTop: '20px'}} onClick={handleGenerate}>
        🎲 Gerar Sorteio
      </button>
    </div>
  );
};

// Tela de Login do Admin (Proteção)
const AdminLogin = ({ correctPin, onUnlock, onReset }: { correctPin: string, onUnlock: () => void, onReset: () => void }) => {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');

  const handleLogin = () => {
    if (pin === correctPin) {
      onUnlock();
    } else {
      setError('PIN Incorreto');
      setPin('');
    }
  };

  return (
    <div className="card fade-in">
      <div className="header-icon">🛡️</div>
      <h2>Acesso do Organizador</h2>
      <p className="text-center">Digite o PIN Mestre definido na criação.</p>
      
      <input 
        type="tel" 
        className="pin-input"
        maxLength={6}
        inputMode="numeric"
        placeholder="••••••"
        value={pin}
        onChange={e => setPin(e.target.value.replace(/\D/g, ''))}
      />
      
      {error && <div className="alert alert-error">{error}</div>}

      <button className="btn btn-primary" onClick={handleLogin}>Acessar Painel</button>
      
      <div style={{marginTop: '30px', borderTop: '1px solid #eee', paddingTop: '15px'}}>
        <p className="text-center text-sm text-gray">Esqueceu o PIN?</p>
        <button className="btn-sm btn-danger" style={{width: '100%'}} onClick={() => {
           if (confirm('Isso apagará o sorteio atual permanentemente do seu navegador. Continuar?')) onReset();
        }}>🗑️ Resetar App</button>
      </div>
    </div>
  );
};

// Tela de Dashboard (Admin)
const AdminDashboard = ({ data, onReset }: { data: StoredDraw, onReset: () => void }) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const getShareLink = (owner: string, token: string) => {
    const baseUrl = "https://sorteioapp-2025.streamlit.app";
    // Encode parameters as Streamlit expects
    return `${baseUrl}/?id=${encodeURIComponent(owner)}&t=${encodeURIComponent(token)}`;
  };

  const getShareMessage = (owner: string, pin: string, token: string) => {
    const link = getShareLink(owner, token);
    let msg = `🎄 *AMIGO SECRETO* 🎄\n\nOlá ${owner}! 🎅\nAqui está seu envelope secreto.\n\n🔗 *Link:* ${link}\n🔑 *Sua Senha:* ${pin}`;
    
    if (data.revealAt) {
      const dateStr = Lib.formatDate(data.revealAt);
      msg += `\n📅 *Revelação:* ${dateStr}`;
    }

    msg += `\n\n_Não compartilhe este link ou senha!_`;
    return msg;
  };

  const handleExport = () => {
    let txt = `BACKUP AMIGO SECRETO [${data.drawId}]\nGerado em: ${Lib.formatDate(data.createdAt)}\n`;
    if (data.revealAt) txt += `Revelação: ${Lib.formatDate(data.revealAt)}\n`;
    txt += `\n`;

    data.pairings.forEach(p => {
      txt += `Nome: ${p.ownerName} | PIN: ${p.pin}\nLink: ${getShareLink(p.ownerName, p.token)}\n------------------\n`;
    });
    const blob = new Blob([txt], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `backup-amigo-secreto-${data.drawId}.txt`;
    a.click();
  };

  return (
    <div className="card fade-in">
      <div className="header-icon">📋📤</div>
      <h2>Painel de Envio</h2>
      <p className="subtitle">Envie os cartões individualmente.</p>

      <div className="list-container">
        {data.pairings.map(p => (
          <div key={p.ownerName} className="list-item">
            <div className="item-info">
              <span className="item-name">{p.ownerName}</span>
              {copiedId === p.ownerName && <span className="badge-sent">Copiado</span>}
            </div>
            
            <div className="copy-area">
                <textarea 
                    readOnly 
                    className="copy-textarea"
                    value={getShareMessage(p.ownerName, p.pin, p.token)}
                    onClick={(e) => (e.target as HTMLTextAreaElement).select()}
                />
                <button 
                    className="btn-sm btn-secondary" 
                    onClick={() => {
                        navigator.clipboard.writeText(getShareMessage(p.ownerName, p.pin, p.token));
                        setCopiedId(p.ownerName);
                    }}
                >
                    📋 Copiar Mensagem
                </button>
            </div>
          </div>
        ))}
      </div>

      <div className="footer-actions">
        <button className="btn-sm btn-outline" onClick={handleExport}>💾 Exportar Backup</button>
        <button className="btn-sm btn-danger" onClick={() => {
          if (confirm('Tem certeza? Isso apagará o sorteio deste dispositivo.')) onReset();
        }}>🗑️ Encerrar Sorteio</button>
      </div>
    </div>
  );
};

// Tela do Participante
const ParticipantView = ({ id, token }: { id: string | null, token: string | null }) => {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [payload, setPayload] = useState<SecurePayload | null>(null);
  const [revealed, setRevealed] = useState(false);
  
  // Rate Limit State
  const [strikes, setStrikes] = useState(0);
  const [blockedUntil, setBlockedUntil] = useState<number | null>(null);

  const safeId = id ? decodeURIComponent(id) : '';

  // Carregar rate limit da sessão
  useEffect(() => {
    if (!safeId) return;
    const key = `ratelimit_${safeId}`;
    const stored = sessionStorage.getItem(key);
    if (stored) {
      const { strikes: s, blockUntil: b } = JSON.parse(stored);
      setStrikes(s);
      if (b && Date.now() < b) setBlockedUntil(b);
    }
  }, [safeId]);

  // Render: Link Inválido/Corrompido
  if (!id || !token) {
    return (
      <div className="card fade-in">
        <div className="header-icon">🔗❌</div>
        <h2>Link Inválido</h2>
        <p className="text-center">Parece que o link está incompleto ou corrompido.</p>
        <p className="text-center text-sm text-gray">Peça um novo link ao organizador.</p>
        <button className="btn btn-outline" style={{marginTop:'20px'}} onClick={() => window.location.href = window.location.pathname}>Ir para Início</button>
      </div>
    );
  }

  const handleUnlock = () => {
    // 1. Check Block
    if (blockedUntil) {
      if (Date.now() < blockedUntil) {
        const seconds = Math.ceil((blockedUntil - Date.now()) / 1000);
        setError(`Muitas tentativas. Aguarde ${seconds}s.`);
        return;
      } else {
        setBlockedUntil(null);
        setStrikes(0);
      }
    }

    if (pin.length !== 6) {
      setError('O PIN deve ter 6 dígitos.');
      return;
    }

    // 2. Try Decrypt
    const result = Lib.decryptPayload(token, pin);

    // 3. Handle Failure
    if (!result) {
      const newStrikes = strikes + 1;
      setStrikes(newStrikes);
      
      let newBlock = null;
      let msg = 'PIN incorreto.';
      
      if (newStrikes >= 3) {
        newBlock = Date.now() + 30000; // 30 segundos
        setBlockedUntil(newBlock);
        msg = 'PIN incorreto. Bloqueado por 30s.';
      }

      sessionStorage.setItem(`ratelimit_${safeId}`, JSON.stringify({ strikes: newStrikes, blockUntil: newBlock }));
      setError(msg);
      return;
    }

    // 4. Validate Integrity (Owner ID check)
    // Garante que o usuário não está tentando abrir o envelope de outra pessoa com a URL errada
    if (result.ownerName !== safeId) {
      setError('Este link não corresponde ao nome informado na URL. Peça um novo link.');
      return;
    }

    // Success
    setPayload(result);
    setError('');
  };

  // Render: Bloqueado por Tempo (Rate Limit)
  if (blockedUntil && Date.now() < blockedUntil) {
    const seconds = Math.ceil((blockedUntil - Date.now()) / 1000);
    return (
      <div className="card fade-in">
        <div className="header-icon">⛔</div>
        <h2>Acesso Bloqueado</h2>
        <p className="text-center">Muitas tentativas incorretas.</p>
        <p className="text-center font-bold">Tente novamente em {seconds}s</p>
      </div>
    );
  }

  // Render: Envelope Aberto (Payload Decifrado)
  if (payload) {
    // Se revealAt for null, libera imediato. Se tiver data, checa.
    const isTimeLocked = payload.revealAt ? payload.revealAt > Date.now() : false;

    if (isTimeLocked && payload.revealAt) {
      return (
        <div className="card fade-in">
          <div className="header-icon">⏳</div>
          <h2>Psiu! Ainda não...</h2>
          <p className="text-center">Seu envelope está seguro, mas a revelação só acontece em:</p>
          <div className="highlight-box warm">
            {Lib.formatDate(payload.revealAt)}
          </div>
          <p className="text-center text-sm text-gray">Volte neste horário!</p>
        </div>
      );
    }

    return (
      <div className="card fade-in">
        <div className="header-icon">{revealed ? '🎉' : '💌'}</div>
        <h2>Olá, {payload.ownerName}!</h2>
        
        {!revealed ? (
          <>
            <p className="text-center">Senha correta. Envelope destrancado.</p>
            <p className="text-center text-sm" style={{marginBottom: '20px'}}>Certifique-se de que ninguém está olhando...</p>
            <button className="btn btn-primary" onClick={() => setRevealed(true)}>
              VER QUEM EU TIREI
            </button>
          </>
        ) : (
          <div className="reveal-animation">
            <p className="text-center text-sm">Seu amigo secreto é...</p>
            <div className="highlight-box result">
              {payload.receiverName}
            </div>
            <p className="text-center text-gray text-sm">Shhh! É segredo. 🤫</p>
            <button 
              className="btn btn-outline" 
              style={{marginTop: '20px'}}
              onClick={() => window.open(`https://www.google.com/search?q=ideia+presente+para+${encodeURIComponent(payload.receiverName)}`, '_blank')}
            >
              🎁 Buscar ideias de presente
            </button>
          </div>
        )}
      </div>
    );
  }

  // Render: Tela de Login
  return (
    <div className="card fade-in">
      <div className="header-icon">🔐</div>
      <h2>Envelope Seguro</h2>
      <p className="text-center">
        Este envelope pertence a <strong>{safeId}</strong>.
      </p>
      <p className="text-center text-sm text-gray">Digite seu PIN de 6 dígitos para abrir.</p>

      <input 
        type="tel" 
        className="pin-input"
        maxLength={6}
        inputMode="numeric"
        placeholder="••••••"
        value={pin}
        onChange={e => setPin(e.target.value.replace(/\D/g, ''))}
      />

      {error && <div className="alert alert-error">{error}</div>}

      <button className="btn btn-primary" onClick={handleUnlock}>
        Abrir Envelope
      </button>
    </div>
  );
};

// App Principal
const App = () => {
  const [view, setView] = useState<'SETUP' | 'ADMIN' | 'PARTICIPANT'>('SETUP');
  const [drawData, setDrawData] = useState<StoredDraw | null>(null);
  const [adminAuthenticated, setAdminAuthenticated] = useState(false);
  
  // Participant Params
  const [pId, setPId] = useState<string | null>(null);
  const [pToken, setPToken] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    const token = params.get('t');

    // Se tiver params, vai para modo participante (mesmo se inválidos, a view trata)
    if (id || token) {
      setPId(id);
      setPToken(token);
      setView('PARTICIPANT');
    } else {
      // Verifica backup do admin
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          setDrawData(parsed);
          setView('ADMIN');
          // Nota: Não autenticamos automaticamente ao recarregar a página
          // O Admin precisa digitar o PIN novamente.
        } catch { setView('SETUP'); }
      } else {
        setView('SETUP');
      }
    }
  }, []);

  const handleGenerate = (names: string[], date: number | null, adminPin: string) => {
    const data = Lib.shuffleAndPair(names, date, adminPin);
    if (data) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
      setDrawData(data);
      setView('ADMIN');
      setAdminAuthenticated(true); // Autentica automaticamente logo após criar
    } else {
      alert('Erro ao gerar sorteio. Tente novamente.');
    }
  };

  const handleRestore = (data: StoredDraw) => {
    setDrawData(data);
    setView('ADMIN');
    setAdminAuthenticated(false); // Exige PIN ao restaurar backup da tela inicial
  };

  const handleReset = () => {
    // 1. Limpa persistência
    localStorage.removeItem(STORAGE_KEY);
    
    // 2. Limpa estados do Admin e Sorteio
    setDrawData(null);
    setAdminAuthenticated(false);
    
    // 3. Limpa estados de Participante (caso existam)
    setPId(null);
    setPToken(null);
    
    // 4. Limpa URL para evitar re-leitura de parâmetros
    window.history.replaceState(null, '', window.location.pathname);
    
    // 5. Redireciona para Setup
    setView('SETUP');
  };

  const handleAdminUnlock = () => {
    setAdminAuthenticated(true);
  };

  // Render Logic
  let content = null;
  if (view === 'PARTICIPANT') {
    content = <ParticipantView id={pId} token={pToken} />;
  } else if (view === 'ADMIN' && drawData) {
    content = !adminAuthenticated 
      ? <AdminLogin correctPin={drawData.adminPin} onUnlock={handleAdminUnlock} onReset={handleReset} />
      : <AdminDashboard data={drawData} onReset={handleReset} />;
  } else {
    content = <AdminSetup onGenerate={handleGenerate} onRestore={handleRestore} />;
  }

  return (
    <div className="app-container">
      {content}
      
      <footer className="footer">
        Amigo Secreto v0.4.0 • Criptografia AES Client-Side<br/>
        Não há armazenamento em servidor. Dados salvos apenas no navegador e no link.
      </footer>
    </div>
  );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
