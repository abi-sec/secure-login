'use strict';

// ── Character counter (feedback page) ────────────────────────────────────────
const msg = document.getElementById('message');
const counter = document.getElementById('charCount');
if (msg && counter) {
  msg.addEventListener('input', () => { counter.textContent = msg.value.length; });
}

// ── Client-side file size check (feedback page) ──────────────────────────────
const fileInput = document.getElementById('attachment');
const fileSizeError = document.getElementById('fileSizeError');
if (fileInput && fileSizeError) {
  const MAX_BYTES = parseInt(fileInput.dataset.maxMb, 10) * 1024 * 1024;
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file && file.size > MAX_BYTES) {
      fileSizeError.style.display = 'block';
      fileInput.value = '';
    } else {
      fileSizeError.style.display = 'none';
    }
  });
}

// ── zxcvbn password strength ──────────────────────────────────────────────────
const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'];
const WIDTHS = ['20%', '40%', '60%', '80%', '100%'];

// Handles both register page (#password) and feedback page (#newPassword)
const pwInput = document.getElementById('password') || document.getElementById('newPassword');
const bar = document.getElementById('strengthBar');
const lbl = document.getElementById('strengthLabel');

if (pwInput && bar && lbl) {
  const defaultLabel = pwInput.id === 'password'
    ? 'Enter a password to see its strength'
    : 'Enter new password';

  pwInput.addEventListener('input', () => {
    if (!pwInput.value) {
      bar.style.width = '0%';
      lbl.textContent = defaultLabel;
      return;
    }
    const result = zxcvbn(pwInput.value);
    const score = result.score;
    bar.style.width = WIDTHS[score];
    bar.style.background = COLORS[score];
    lbl.textContent = `Strength: ${LABELS[score]}`;
    if (result.feedback.warning) {
      lbl.textContent += ` — ${result.feedback.warning}`;
    }
  });
}