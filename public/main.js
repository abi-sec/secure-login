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

// ── Listing image preview + validation (listing page) ────────────────────────
const imagesInput = document.getElementById('images');
const previewGrid = document.getElementById('previewGrid');
const fileError = document.getElementById('fileError');

if (imagesInput && previewGrid) {
  const MAX_BYTES_IMG = parseInt(imagesInput.dataset.maxMb, 10) * 1024 * 1024;
  const MAX_FILES = 5;

  imagesInput.addEventListener('change', () => {
    previewGrid.innerHTML = '';
    fileError.style.display = 'none';
    fileError.textContent = '';

    const files = Array.from(imagesInput.files);

    if (files.length > MAX_FILES) {
      fileError.textContent = `Maximum ${MAX_FILES} images allowed.`;
      fileError.style.display = 'block';
      imagesInput.value = '';
      return;
    }

    for (const file of files) {
      if (file.size > MAX_BYTES_IMG) {
        fileError.textContent = `"${file.name}" exceeds the ${imagesInput.dataset.maxMb}MB size limit.`;
        fileError.style.display = 'block';
        imagesInput.value = '';
        previewGrid.innerHTML = '';
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        const img = document.createElement('img');
        img.src = e.target.result;
        img.className = 'preview-img';
        img.alt = file.name;
        previewGrid.appendChild(img);
      };
      reader.readAsDataURL(file);
    }
  });
}

// ── Carousel (home page) ──────────────────────────────────────────────────────
const carouselState = {};

function carouselGoTo(index, slide) {
  if (!carouselState[index]) carouselState[index] = { current: 0 };
  const track = document.getElementById('track-' + index);
  const dots = document.querySelectorAll('#dots-' + index + ' .carousel-dot');
  if (!track) return;
  const total = track.children.length;

  slide = Math.max(0, Math.min(slide, total - 1));
  carouselState[index].current = slide;

  track.style.transform = 'translateX(-' + (slide * 100) + '%)';
  dots.forEach((d, i) => d.classList.toggle('active', i === slide));
}

function carouselMove(index, direction) {
  if (!carouselState[index]) carouselState[index] = { current: 0 };
  const track = document.getElementById('track-' + index);
  if (!track) return;
  const total = track.children.length;
  const next = (carouselState[index].current + direction + total) % total;
  carouselGoTo(index, next);
}

// Expose to HTML onclick attributes via data attributes instead
// Wire up all carousels on page load
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-carousel-prev]').forEach(btn => {
    btn.addEventListener('click', () => {
      carouselMove(parseInt(btn.dataset.carouselPrev), -1);
    });
  });

  document.querySelectorAll('[data-carousel-next]').forEach(btn => {
    btn.addEventListener('click', () => {
      carouselMove(parseInt(btn.dataset.carouselNext), 1);
    });
  });

  document.querySelectorAll('[data-carousel-dot]').forEach(btn => {
    btn.addEventListener('click', () => {
      carouselGoTo(
        parseInt(btn.dataset.carouselIndex),
        parseInt(btn.dataset.carouselDot)
      );
    });
  });
});

// ── zxcvbn password strength ──────────────────────────────────────────────────
const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'];
const WIDTHS = ['20%', '40%', '60%', '80%', '100%'];

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