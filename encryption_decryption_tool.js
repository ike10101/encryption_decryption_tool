document.addEventListener('DOMContentLoaded', () => {
  const algorithmSelect = document.getElementById('algorithm-select');
  const algorithmHint = document.getElementById('algorithm-hint');
  const keyGroup = document.getElementById('key-group');
  const keyInput = document.getElementById('key-input');
  const toggleKeyBtn = document.getElementById('toggle-key-btn');
  const toggleKeyIcon = document.getElementById('toggle-key-icon');
  const textInput = document.getElementById('text-input');
  const textOutput = document.getElementById('text-output');
  const encryptBtn = document.getElementById('encrypt-btn');
  const decryptBtn = document.getElementById('decrypt-btn');
  const copyBtn = document.getElementById('copy-btn');
  const downloadBtn = document.getElementById('download-btn');
  const clearInputBtn = document.getElementById('clear-input-btn');
  const clearOutputBtn = document.getElementById('clear-output-btn');
  const statusMessage = document.getElementById('status-message');

  const BACKEND_URL = 'http://127.0.0.1:5000/api';

  const cipherInfo = {
    aes_cbc: { hint: "Requires key/password. Uses AES in CBC mode." },
    aes_ctr: { hint: "Requires key/password. Uses AES in Counter mode." },
    aes_gcm: { hint: "Requires key/password. Uses AES in GCM mode." },
    autokey: { hint: "Requires text keyword." },
    chacha20: { hint: "Requires key/password. Uses ChaCha20-Poly1305." },
    columnar: { hint: "Requires key word/phrase." },
    fernet: { hint: "Requires key/passphrase." },
    playfair: { hint: "Requires key word/phrase." },
    vigenere: { hint: "Requires alphabetic key phrase." }
  };

  function updateAlgorithmUI() {
    const selected = algorithmSelect.value;
    const config = cipherInfo[selected] || { hint: '' };
    algorithmHint.textContent = config.hint;
  }

  algorithmSelect.addEventListener('change', updateAlgorithmUI);
  updateAlgorithmUI();

  toggleKeyBtn.addEventListener('click', () => {
    const isPassword = keyInput.type === 'password';
    keyInput.type = isPassword ? 'text' : 'password';
    toggleKeyIcon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
  });

  function showStatus(message, type = 'error') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
  }

  function hideStatus() {
    statusMessage.className = 'status-message hidden';
  }

  async function processCipher(action) {
    hideStatus();
    const algorithm = algorithmSelect.value;
    const text = textInput.value.trim();
    const key = keyInput.value.trim();

    if (!text) {
      showStatus('Please enter text to process.', 'error');
      return;
    }

    if (!key) {
      showStatus('Secret key or password is required.', 'error');
      return;
    }

    const targetBtn = action === 'encrypt' ? encryptBtn : decryptBtn;
    const originalText = targetBtn.innerHTML;
    targetBtn.disabled = true;
    targetBtn.innerHTML = `Processing...`;

    try {
      const response = await fetch(`${BACKEND_URL}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm, text, key })
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        showStatus(data.error || 'An error occurred during calculation.', 'error');
        textOutput.value = '';
      } else {
        textOutput.value = data.result;
        showStatus(`Success!`, 'success');
      }
    } catch (err) {
      showStatus('Unable to reach local backend server.', 'error');
    } finally {
      targetBtn.disabled = false;
      targetBtn.innerHTML = originalText;
    }
  }

  encryptBtn.addEventListener('click', () => processCipher('encrypt'));
  decryptBtn.addEventListener('click', () => processCipher('decrypt'));

  clearInputBtn.addEventListener('click', () => {
    textInput.value = '';
    hideStatus();
  });

  clearOutputBtn.addEventListener('click', () => {
    textOutput.value = '';
    hideStatus();
  });

  copyBtn.addEventListener('click', () => {
    if (!textOutput.value) {
      showStatus('No output text to copy.', 'error');
      return;
    }
    textOutput.select();
    try {
      document.execCommand('copy');
      showStatus('Copied to clipboard!', 'success');
    } catch (err) {
      showStatus('Failed to copy.', 'error');
    }
  });

  downloadBtn.addEventListener('click', () => {
    const text = textOutput.value;
    if (!text) {
      showStatus('No output text to download.', 'error');
      return;
    }

    const algo = algorithmSelect.value;
    const filename = `${algo}_result.txt`;
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    
    const element = document.createElement('a');
    element.setAttribute('href', URL.createObjectURL(blob));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    
    showStatus(`Saved as ${filename}`, 'success');
  });
});