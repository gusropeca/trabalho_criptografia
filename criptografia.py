import streamlit as st
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import psycopg2
from datetime import datetime
import uuid
import os
import requests
import streamlit.components.v1 as components
import time


def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "IP não disponível"



def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", "5432")
    )


# Funções de criptografia
def encrypt_message(message, algorithm, key=None):
    if algorithm == "DES":
        key = get_random_bytes(8)
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_text = pad(message.encode('utf-8'), DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return {
            'algorithm': 'DES',
            'data': base64.b64encode(iv + ciphertext).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    elif algorithm == "AES":
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_text = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return {
            'algorithm': 'AES',
            'data': base64.b64encode(iv + ciphertext).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    elif algorithm == "RSA":
       
        sender_private_key = RSA.import_key(st.session_state.rsa_keys['private'])
        sender_public_key = RSA.import_key(st.session_state.rsa_keys['public'])

        # Criptografa a mensagem com a chave pública do destinatário (simulado como o próprio)
        cipher = PKCS1_OAEP.new(sender_public_key)
        encrypted = cipher.encrypt(message.encode('utf-8'))

        # Assina com a chave privada do remetente
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256

        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(sender_private_key).sign(h)

        return {
            'algorithm': 'RSA',
            'data': base64.b64encode(encrypted).decode('utf-8'),
            'key': None,
            'signature': base64.b64encode(signature).decode('utf-8')
        }



def decrypt_message(package):
    algorithm = package['algorithm']
    encrypted_data = base64.b64decode(package['data'])
    
    if algorithm == "DES":
        key = base64.b64decode(package['key'])
        iv, ciphertext = encrypted_data[:8], encrypted_data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return decrypted.decode('utf-8')
    
    elif algorithm == "AES":
        key = base64.b64decode(package['key'])
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')
    
    elif algorithm == "RSA":
        private_key = RSA.import_key(st.session_state.rsa_keys['private'])

        # Descriptografa a mensagem com a chave privada
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted_data)
        decrypted_text = decrypted.decode('utf-8')

        # Verifica a assinatura (usa a chave pública do REMETENTE)
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256

        signature_b64 = package.get('signature')
        if not signature_b64:
            return f"[⚠️ Mensagem sem assinatura]\n\n{decrypted_text}"

        try:
            signature = base64.b64decode(signature_b64)
            h = SHA256.new(decrypted_text.encode('utf-8'))

            # Aqui, você precisa da CHAVE PÚBLICA do remetente
            # Como você não está salvando isso no banco, vamos usar a própria, mas o ideal seria salvar isso no envio
            sender_public_key = RSA.import_key(st.session_state.rsa_keys['public'])

            pkcs1_15.new(sender_public_key).verify(h, signature)
            return f"[✅ Mensagem Autêntica]\n\n{decrypted_text}"
        except (ValueError, TypeError):
            return f"[❌ Assinatura Inválida]\n\n{decrypted_text}"

# Inicialização
if 'rsa_keys' not in st.session_state:
    key = RSA.generate(2048)
    st.session_state.rsa_keys = {
        'private': key.export_key(),
        'public': key.publickey().export_key()
    }

# Cria a tabela no PostgreSQL
def init_db():
    """Cria a tabela se não existir e adiciona coluna 'signature' se necessário"""
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return False

        with conn.cursor() as cur:
            # Cria a tabela se não existir
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(50) PRIMARY KEY,
                    algorithm VARCHAR(10) NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    key TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            conn.commit()

            # Verifica se a coluna 'signature' existe
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='messages' AND column_name='signature';
            """)
            exists = cur.fetchone()

            # Se não existir, adiciona a coluna
            if not exists:  
                cur.execute("ALTER TABLE messages ADD COLUMN signature TEXT;")
                conn.commit()
                
               # Adiciona coluna sender_ip se necessário
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='messages' AND column_name='sender_ip';
            """)
            if not cur.fetchone():
                cur.execute("ALTER TABLE messages ADD COLUMN sender_ip TEXT;")
                conn.commit()
 

        return True

    except Exception as e:
        st.error(f"Erro ao criar tabela: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()


init_db()

# Interface Streamlit
st.title("🔐 Sistema de Comunicação Criptografada")

st.markdown("### 📡 Capturando seu IP real...")

# Espaço reservado para exibir o IP
ip_placeholder = st.empty()

# Container oculto para armazenar o IP
if "client_ip" not in st.session_state:
    st.session_state.client_ip = None

# HTML + JS para capturar o IP do navegador e enviar para o Python
components.html(
    """
    <script>
    fetch("https://api.ipify.org/?format=json")
        .then(response => response.json())
        .then(data => {
            const ip = data.ip;
            const streamlitInput = window.parent.document.querySelector('iframe[title="streamlit.components.v1.html"]').parentElement;
            streamlitInput.setAttribute("data-ip", ip);
            window.parent.postMessage({type: "streamlit:setComponentValue", value: ip}, "*");
        });
    </script>
    """,
    height=0,
)

# Aguarda IP por até 3 segundos
if st.session_state.client_ip is None:
    for _ in range(30):
        if "_component_value" in st.session_state:
            st.session_state.client_ip = st.session_state._component_value
            break
        time.sleep(0.1)

if st.session_state.client_ip:
    ip_placeholder.success(f"🌐 Seu IP : `{st.session_state.client_ip}`")
else:
    ip_placeholder.error("❌ Não foi possível obter seu IP.")



tab1, tab2 = st.tabs(["🔒 Remetente", "🔓 Destinatário"])

with tab1:
    st.header("Criptografar Mensagem")
    message = st.text_area("Digite sua mensagem:")
    algorithm = st.radio("Algoritmo:", ("AES", "DES", "RSA"), horizontal=True)
    
    if st.button("🛫 Enviar Mensagem Criptografada"):
        if message:
            encrypted = encrypt_message(message, algorithm)
            
            
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                signature = encrypted.get('signature')  # Pode ser None para AES e DES
                sender_ip = st.session_state.get("client_ip", "IP não identificado")


                cur.execute(
                    "INSERT INTO messages (id, algorithm, encrypted_data, key, signature, sender_ip) VALUES (%s, %s, %s, %s, %s, %s)",
                    (str(uuid.uuid4()), algorithm, encrypted['data'], encrypted['key'], signature, sender_ip)
                )


                conn.commit()
                st.success("Mensagem criptografada e armazenada no banco de dados!")
                
                if algorithm in ["AES", "DES"]:
                    st.warning(f"🔑 Chave necessária para descriptografia: {encrypted['key']}")
                else:
                    st.info("✔️ Mensagem RSA - Chave privada já está com o destinatário")
                    
            except Exception as e:
                st.error(f"Erro ao salvar no banco de dados: {e}")
            finally:
                if conn:
                    conn.close()
        else:
            st.warning("Por favor, digite uma mensagem")

with tab2:
    st.header("Descriptografar Mensagem")
    with st.expander("⚠️ Limpeza de Mensagens"):
        if st.button("🗑️ Apagar todas as mensagens"):
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM messages")
                conn.commit()
                st.success("Todas as mensagens foram apagadas com sucesso.")
            except Exception as e:
                st.error(f"Erro ao apagar mensagens: {e}")
            finally:
                if conn:
                    conn.close()

    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, algorithm FROM messages ORDER BY created_at DESC")
        messages = cur.fetchall()
        
        if messages:
            selected_id = st.selectbox(
                "Selecione a mensagem:",
                options=[msg[0] for msg in messages],
                format_func=lambda x: f"ID: {x[:8]}... (Algoritmo: {next(m[1] for m in messages if m[0] == x)})"
            )
            
            if selected_id:
                cur.execute("SELECT algorithm, encrypted_data, key, signature, sender_ip FROM messages WHERE id = %s", (selected_id,))
                algorithm, encrypted_data, key, signature, sender_ip = cur.fetchone()


                
                if algorithm in ["AES", "DES"]:
                    input_key = st.text_input(f"Insira a chave {algorithm}:")
                else:
                    input_key = None
                
                if st.button("🔓 Descriptografar"):
                    try:                     
                        decrypted = decrypt_message({
                        'algorithm': algorithm,
                        'data': encrypted_data,
                        'key': input_key if algorithm in ["AES", "DES"] else None,
                        'signature': signature if algorithm == "RSA" else None
                    })
                        receiver_ip = get_public_ip()

                        # Mostra a mensagem
                        st.success("Mensagem descriptografada com sucesso!")
                        st.text_area("Texto original:", value=decrypted, height=100)

                        # Mostra os IPs
                        st.markdown(f"📡 **IP do Remetente:** `{sender_ip}`")
                        st.markdown(f"📥 **IP do Destinatário (você):** `{receiver_ip}`")

                    except Exception as e:
                        st.error(f"Falha na descriptografia: {str(e)}")
        else:
            st.info("Nenhuma mensagem encontrada no banco de dados.")
            
    except Exception as e:
        st.error(f"Erro ao acessar banco de dados: {e}")
    finally:
        if conn:
            conn.close()

st.markdown("---")
st.caption("🔒 Sistema seguro - Mensagens armazenadas no PostgreSQL | " + datetime.now().strftime("%d/%m/%Y %H:%M"))
