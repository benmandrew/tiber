import init, { encrypt_rounds, decrypt_rounds } from '../pkg/tiber_wasm.js';
await init();

// ---------- Formatting ----------
function formatHex(raw) {
  return raw
    .replace(/[^0-9a-fA-F]/g, '')
    .match(/.{1,2}/g)
    ?.join(' ') ?? '';
}

function enableHexFormatting(input) {
  if (input._hexHandlers) return;

  input.classList.add('hex');

  const keydownHandler = (e) => {
    if (e.key !== 'Backspace') return;
    const pos = input.selectionStart;
    const value = input.value;
    if (input.selectionStart !== input.selectionEnd){
      return;
    }
    if (pos > 0 && value[pos - 1] === ' ') {
      e.preventDefault();
      input.value =
        value.slice(0, pos - 2) +
        value.slice(pos);
      const newPos = pos - 2;
      input.setSelectionRange(newPos, newPos);
    }
  };

  const inputHandler = () => {
    const cursor = input.selectionStart;
    const rawBeforeCursor = input.value
      .slice(0, cursor)
      .replace(/ /g, '').length;
    const raw = input.value.replace(/ /g, '');
    const formatted = formatHex(raw);
    input.value = formatted;
    const newCursor = rawBeforeCursor + Math.floor(rawBeforeCursor / 2);
    input.setSelectionRange(newCursor, newCursor);
  };

  input.addEventListener('keydown', keydownHandler);
  input.addEventListener('input', inputHandler);

  input._hexHandlers = { keydownHandler, inputHandler };

  input.value = formatHex(input.value);
}

function disableHexFormatting(input) {
  if (!input._hexHandlers) return;

  const { keydownHandler, inputHandler } = input._hexHandlers;

  input.removeEventListener('keydown', keydownHandler);
  input.removeEventListener('input', inputHandler);

  input._hexHandlers = null;

  input.classList.remove('hex');
}

// ---------- Conversion ----------
function asciiToHex(str) {
  return Array.from(str)
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

function hexToAscii(hex) {
  hex = hex.replace(/ /g, '');
  if (hex.length % 2 !== 0) {
    return '';
  }
  let out = '';
  for (let i = 0; i < hex.length; i += 2) {
    out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

function hexToBytes(hex, padTo = 0) {
  hex = hex.replace(/ /g, '');
  if (hex.length % 2 !== 0) {
    return null;
  }
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  while (bytes.length < padTo) bytes.push(0);
  return new Uint8Array(bytes);
}

function asciiToBytes(str, padTo = 0) {
  if (str.length > padTo) return null;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    bytes.push(str.charCodeAt(i));
  }
  while (bytes.length < padTo) bytes.push(0);
  return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------- Setup ----------
const keyInput = document.getElementById('key');
const ptInput = document.getElementById('plaintext');

enableHexFormatting(keyInput); // key always hex

document.querySelectorAll('input[name="pt-format"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const current = ptInput.value;
    if (radio.value === 'hex') {
      // ASCII to hex
      const hex = asciiToHex(current);
      ptInput.value = hex;
      ptInput.maxLength = 47;
      enableHexFormatting(ptInput);
    } else {
      // Hex to ASCII
      const ascii = hexToAscii(current);
      disableHexFormatting(ptInput);
      ptInput.value = ascii;
      ptInput.maxLength = 16;
    }
  });
});

// ---------- Logic ----------
function getPlaintext() {
  const format = document.querySelector('input[name="pt-format"]:checked').value;
  const val = ptInput.value;
  return format === 'hex'
    ? hexToBytes(val, 16)
    : asciiToBytes(val, 16);
}

function showRounds(rounds) {
  const div = document.getElementById('rounds');
  div.innerHTML = '';
  rounds.forEach((state, i) => {
    const el = document.createElement('div');
    el.className = 'round';
    el.textContent = `Round ${i}: ${bytesToHex(state)}`;
    div.appendChild(el);
  });
}

document.getElementById('encrypt').onclick = () => {
  const key = hexToBytes(keyInput.value, 16);
  const pt = getPlaintext();
  if (!key || key.length !== 16 || !pt || pt.length !== 16) {
    const format = document.querySelector('input[name="pt-format"]:checked').value;
    alert(format === 'hex'
      ? 'Invalid hex input'
      : 'Plaintext must be ≤16 ASCII chars');
    return;
  }
  showRounds(encrypt_rounds(pt, key));
};

document.getElementById('decrypt').onclick = () => {
  const key = hexToBytes(keyInput.value, 16);
  const ct = getPlaintext();
  if (!key || key.length !== 16 || !ct || ct.length !== 16) {
    const format = document.querySelector('input[name="pt-format"]:checked').value;
    alert(format === 'hex'
      ? 'Invalid hex input'
      : 'Ciphertext must be ≤16 ASCII chars');
    return;
  }
  showRounds(decrypt_rounds(ct, key));
};
