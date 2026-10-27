'use strict';

(function () {
  const BACKEND_URL = 'http://127.0.0.1:5000/api';
  const REQUEST_TIMEOUT_MS = 20000;

  const cipherHints = {
    aes_cbc: 'Requires a key/password. AES in CBC mode (no tamper detection). Output is Base64.',
    aes_ctr: 'Requires a key/password. AES in Counter mode (no tamper detection). Output is Base64.',
    aes_gcm: 'Requires a key/password. AES in GCM mode (authenticated). Output is Base64.',
    autokey: 'Requires a keyword made of letters (A-Z). Only letters are changed; other characters are kept.',
    chacha20: 'Requires a key/password. ChaCha20-Poly1305 (authenticated). Output is Base64.',
    columnar: 'Requires a key word/phrase of at least 2 characters (spaces are ignored).',
    fernet: 'Requires a key/passphrase. Fernet (AES-128-CBC + HMAC). Output is a text token.',
    playfair: 'Requires a keyword made of letters (A-Z). Output is capital letters only: spaces, digits and punctuation are dropped, J becomes I, and filler X/Q letters are added.',
    vigenere: 'Requires an alphabetic key phrase (A-Z). Only letters are changed; other characters are kept.'
  };

  const el = (id) => document.getElementById(id);

  const algorithmSelect = el('algorithm-select');
  const algorithmHint = el('algorithm-hint');
  const keyInput = el('key-input');
  const toggleKeyBtn = el('toggle-key-btn');
  const iconEye = el('icon-eye');
  const iconEyeOff = el('icon-eye-off');
  const textInput = el('text-input');
  const textOutput = el('text-output');
  const encryptBtn = el('encrypt-btn');
  const decryptBtn = el('decrypt-btn');
  const copyBtn = el('copy-btn');
  const downloadBtn = el('download-btn');
  const clearInputBtn = el('clear-input-btn');
  const clearOutputBtn = el('clear-output-btn');
  const statusMessage = el('status-message');

  let lastResult = null;

  function updateAlgorithmUI() {
    algorithmHint.textContent = cipherHints[algorithmSelect.value] || '';
  }

  function showStatus(message, type = 'error') {
    statusMessage.textContent = message;
    statusMessage.className = 'status-message ' + type;
  }

  function hideStatus() {
    statusMessage.textContent = '';
    statusMessage.className = 'status-message hidden';
  }

  function setBusy(isBusy, activeBtn) {
    [encryptBtn, decryptBtn].forEach((btn) => {
      btn.disabled = isBusy;
    });
    if (isBusy) {
      activeBtn.dataset.label = activeBtn.textContent;
      activeBtn.textContent = 'Processing...';
    } else {
      [encryptBtn, decryptBtn].forEach((btn) => {
        if (btn.dataset.label) {
          btn.textContent = btn.dataset.label;
          delete btn.dataset.label;
        }
      });
    }
  }

  function setKeyVisible(visible) {
    keyInput.type = visible ? 'text' : 'password';
    iconEye.hidden = visible;
    iconEyeOff.hidden = !visible;
    const label = visible ? 'Hide key' : 'Show key';
    toggleKeyBtn.title = label;
    toggleKeyBtn.setAttribute('aria-label', label);
    toggleKeyBtn.setAttribute('aria-pressed', String(visible));
  }

  async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    textOutput.focus();
    textOutput.select();
    textOutput.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    textOutput.setSelectionRange(0, 0);
    if (!ok) {
      throw new Error('Copy command was rejected');
    }
  }

  async function processCipher(action) {
    hideStatus();

    const algorithm = algorithmSelect.value;
    const rawText = textInput.value;
    const key = keyInput.value;

    if (!rawText.trim()) {
      showStatus('Please enter text to process.', 'error');
      return;
    }
    if (!key.trim()) {
      showStatus('Secret key or password is required.', 'error');
      return;
    }

    const text = rawText;
    const activeBtn = action === 'encrypt' ? encryptBtn : decryptBtn;

    setBusy(true, activeBtn);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(BACKEND_URL + '/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm, text, key }),
        signal: controller.signal
      });

      let data = null;
      try {
        data = await response.json();
      } catch (parseErr) {
        data = null;
      }

      if (!response.ok || !data || data.error) {
        textOutput.value = '';
        lastResult = null;
        showStatus((data && data.error) || ('The server returned an unexpected response (' + response.status + ').'), 'error');
      } else {
        textOutput.value = data.result;
        lastResult = { algorithm, action };
        showStatus(action === 'encrypt' ? 'Text encrypted successfully.' : 'Text decrypted successfully.', 'success');
      }
    } catch (err) {
      textOutput.value = '';
      lastResult = null;
      if (err && err.name === 'AbortError') {
        showStatus('The server took too long to respond. Please try again.', 'error');
      } else {
        showStatus('Unable to reach the local backend. Make sure app.py is running at http://127.0.0.1:5000.', 'error');
      }
    } finally {
      clearTimeout(timer);
      setBusy(false);
    }
  }

  algorithmSelect.addEventListener('change', updateAlgorithmUI);
  updateAlgorithmUI();

  toggleKeyBtn.addEventListener('click', () => {
    setKeyVisible(keyInput.type === 'password');
  });

  encryptBtn.addEventListener('click', () => processCipher('encrypt'));
  decryptBtn.addEventListener('click', () => processCipher('decrypt'));

  clearInputBtn.addEventListener('click', () => {
    textInput.value = '';
    hideStatus();
    textInput.focus();
  });

  clearOutputBtn.addEventListener('click', () => {
    textOutput.value = '';
    lastResult = null;
    hideStatus();
  });

  copyBtn.addEventListener('click', async () => {
    if (!textOutput.value) {
      showStatus('No output text to copy.', 'error');
      return;
    }
    try {
      await copyToClipboard(textOutput.value);
      showStatus('Copied to clipboard!', 'success');
    } catch (err) {
      showStatus('Failed to copy. Select the text and copy it manually.', 'error');
    }
  });

  downloadBtn.addEventListener('click', () => {
    const text = textOutput.value;
    if (!text) {
      showStatus('No output text to download.', 'error');
      return;
    }

    const algo = lastResult ? lastResult.algorithm : algorithmSelect.value;
    let suffix = 'result';
    if (lastResult) {
      suffix = lastResult.action === 'encrypt' ? 'encrypted' : 'decrypted';
    }
    const filename = algo + '_' + suffix + '.txt';

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    showStatus('Saved as ' + filename, 'success');
  });
})();
