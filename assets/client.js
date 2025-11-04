/*
 * Copyright (C) 2025 epha-ots authors
 *
 * This file is part of epha-ots.
 *
 * epha-ots is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * epha-ots is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with epha-ots.  If not, see <https://www.gnu.org/licenses/>.
 */
// SPDX-License-Identifier: GPL-3.0-or-later

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });
const HKDF_INFO_ID = encoder.encode('blob-id');
const ID_REGEX = /^[A-Za-z0-9_-]{16,}$/;

const KEY_SIZE = 32;
const NONCE_SIZE = 12;
const SALT_SIZE = 16;
const ID_SIZE = 16;
const BLOB_TYPE_SIZE = 2;
const BLOB_TYPE_TEXT = new Uint8Array([0x13, 0x37]);
const BLOB_TYPE_PASSWORD = new Uint8Array([0x73, 0x37]);
const BLOB_TYPE_TEXT_VALUE = 0x1337;
const BLOB_TYPE_PASSWORD_VALUE = 0x7337;
const BLOB_SIZE_MAX = 128 * 1024; // 128 KiB
const PBKDF2_ITERATIONS = 800000;
const PBKDF2_HASH = 'SHA-256';
const HKDF_HASH = 'SHA-256';

const QRCODE_SIZE = 220;
const QRCODE_BORDER = 10;
const QRCODE_CORRECT_LEVEL = 1; // 0 for L, !0 for H

const state = {
	id: null,
	bK: null,
	link: null, // share link
	qrVisible: false,
	pendingSecret: null,
	originalPlaceholder: null,
};
let qrInstance = null;
const STATUS_ICON_PATHS = {
	success:
		'<path d="M5 13l4 4L19 7" stroke-linecap="round" stroke-linejoin="round"/>',
	error: '<path d="M12 7v7" stroke-linecap="round" stroke-linejoin="round"/>' +
		       '<path d="M12 17h.01" stroke-linecap="round" stroke-linejoin="round"/>',
	info: '<path d="M12 8h.01" stroke-linecap="round" stroke-linejoin="round"/>' +
		      '<path d="M11 12h1v4h1" stroke-linecap="round" stroke-linejoin="round"/>'
};
const isMacLike = (() => {
	if (typeof navigator === 'undefined')
		return false;
	const id = navigator.platform || navigator.userAgent || '';
	return /(Mac|iPhone|iPad|iPod)/i.test(id);
})();

function normalizeOrigin(origin)
{
	return origin.replace(/\/+$/, '');
}

function clearLocationHash()
{
	if (typeof window === 'undefined')
		return;
	try {
		if (typeof history !== 'undefined' &&
		    typeof history.replaceState === 'function') {
			const path = window.location.pathname +
				     window.location.search;
			history.replaceState(null, '', path);
		} else {
			window.location.hash = '';
		}
	} catch {
		window.location.hash = '';
	}
}

function setStatus(msg, ok = false)
{
	const wrap = $('statusNotification');
	const message = $('statusMessage');
	const subtitle = $('heroSubtitle');
	const iconHolder = $('statusIcon');
	const iconSvg =
		iconHolder ? iconHolder.querySelector('.status-icon-graphic') :
			     null;
	const progress = $('progressBar');

	if (!msg) {
		message.textContent = '';
		wrap.classList.remove('is-visible', 'is-success', 'is-error');
		progress.style.width = '0%';
		iconSvg.innerHTML = '';
		subtitle.classList.remove('is-hidden');
		return;
	}

	message.textContent = msg;
	wrap.classList.add('is-visible');
	wrap.classList.toggle('is-success', !!ok);
	wrap.classList.toggle('is-error', !ok);
	subtitle.classList.add('is-hidden');

	const iconKey = ok ? 'success' : 'error';
	iconSvg.innerHTML = STATUS_ICON_PATHS[iconKey] ||
			    STATUS_ICON_PATHS.info || '';

	progress.style.transition = 'none';
	progress.style.width = '0%';
	void progress.offsetWidth;
	progress.style.transition = '';
	progress.style.width = '100%';
}

function clearPendingSecret()
{
	const pending = state.pendingSecret;
	if (!pending)
		return;
	if (pending.ciphertext)
		pending.ciphertext.fill(0);
	if (pending.nonce)
		pending.nonce.fill(0);
	if (pending.salt)
		pending.salt.fill(0);
	state.pendingSecret = null;
}

function setDecryptionCardVisible(visible)
{
	const deCard = $('decryptionCard');
	const enCard = $('encryptionCard');
	if (visible) {
		deCard.classList.add('is-visible');
		enCard.classList.remove('is-visible');
	} else {
		deCard.classList.remove('is-visible');
		enCard.classList.add('is-visible');
		const pwd = $('decryptionPassword');
		if (pwd)
			pwd.value = '';
	}
}

function lockTextarea(lock)
{
	const textField = $('text');
	if (state.originalPlaceholder === null) {
		const initial = textField.getAttribute('placeholder');
		state.originalPlaceholder =
			typeof initial === 'string' ? initial : '';
	}
	if (lock) {
		textField.classList.add('textarea-locked');
		textField.setAttribute('readonly', 'true');
		textField.setAttribute(
			'placeholder',
			'Secret will appear here after you decrypt it.');
	} else {
		textField.classList.remove('textarea-locked');
		textField.removeAttribute('readonly');
		if (state.originalPlaceholder !== null) {
			if (state.originalPlaceholder === '') {
				textField.removeAttribute('placeholder');
			} else {
				textField.setAttribute(
					'placeholder',
					state.originalPlaceholder);
			}
		}
	}
	textField.dispatchEvent(new Event('input', { bubbles: true }));
}

function cloneBytes(view)
{
	if (!(view instanceof Uint8Array))
		return null;
	const copy = new Uint8Array(view.length);
	copy.set(view);
	return copy;
}

function bytesToHex(bytes)
{
	let out = '';
	for (let i = 0; i < bytes.length; i++)
		out += bytes[i].toString(16).padStart(2, '0');
	return out;
}

function equal16B(a, b)
{
	const wa = new Uint32Array(a.buffer, a.byteOffset, 4);
	const wb = new Uint32Array(b.buffer, b.byteOffset, 4);
	return !((wa[0] ^ wb[0]) | (wa[1] ^ wb[1]) | (wa[2] ^ wb[2]) |
		 (wa[3] ^ wb[3]));
}

function updateQr()
{
	const wrap = $('qrWrap');
	const container = $('qrCode');
	if (!wrap || !container)
		return;
	const qrTarget = state.link;
	if (!state.qrVisible || !qrTarget) {
		wrap.style.display = 'none';
		if (qrInstance && typeof qrInstance.clear === 'function') {
			qrInstance.clear();
		}
		container.innerHTML = '';
		qrInstance = null;
		return;
	}
	try {
		if (typeof window.QRCode !== 'function')
			throw new Error('QR renderer unavailable');
		if (!qrInstance) {
			qrInstance = new QRCode(container, {
				width: QRCODE_SIZE,
				height: QRCODE_SIZE,
				border: QRCODE_BORDER,
				colorDark: '#000000',
				colorLight: '#ffffff',
				correctLevel: QRCODE_CORRECT_LEVEL == 0 ?
						      QRCode.CorrectLevel.L :
						      QRCode.CorrectLevel.H,
			});
		} else if (typeof qrInstance.clear === 'function') {
			qrInstance.clear();
		}
		qrInstance.makeCode(qrTarget);
		wrap.style.display = 'flex';
	} catch (err) {
		console.error(err);
		wrap.style.display = 'none';
		if (qrInstance && typeof qrInstance.clear === 'function')
			qrInstance.clear();
		container.innerHTML = '';
		qrInstance = null;
		state.qrVisible = false;
		const btn = $('btnGenerateQr');
		if (btn)
			btn.textContent = 'Generate QR';
		setStatus(err.message || String(err));
	}
}

function setLink(origin, id, bK)
{
	const wrap = $('generatedWrap');
	const input = $('generatedUrl');
	const copyBtn = $('btnCopyLink');
	const qrBtn = $('btnGenerateQr');

	const reset = () => {
		state.id = null;
		state.bK = null;
		state.link = null;
		state.qrVisible = false;
		if (wrap)
			wrap.style.display = 'none';
		if (input)
			input.value = '';
		if (copyBtn)
			copyBtn.style.display = 'none';
		if (qrBtn) {
			qrBtn.style.display = 'none';
			qrBtn.textContent = 'Generate QR';
		}
	};

	if (!origin || !id || !bK) {
		reset();
		updateQr();
		return;
	}

	let keyBytes = null;
	let idBytes = null;
	try {
		const normalized = normalizeOrigin(origin);
		keyBytes = base64UrlDecode(bK);
		if (!keyBytes || keyBytes.length !== KEY_SIZE)
			throw new Error('Key length mismatch');
		idBytes = base64UrlDecode(id);
		if (!idBytes || idBytes.length !== ID_SIZE)
			throw new Error('ID length mismatch');

		const keyBase64Url = base64UrlEncode(keyBytes);
		const idBase64Url = base64UrlEncode(idBytes);
		state.link =
			normalized + '/#' + idBase64Url + '/' + keyBase64Url;
		state.id = idBase64Url;
		state.bK = keyBase64Url;

		if (wrap)
			wrap.style.display = 'flex';
		if (input)
			input.value = state.link;
		if (copyBtn)
			copyBtn.style.display = 'inline-block';
		const host = $('host');
		if (host)
			host.value = normalized;
	} catch (err) {
		console.error(err);
		setStatus(err.message || String(err));
		reset();
		updateQr();
		return;
	} finally {
		if (keyBytes)
			keyBytes.fill(0);
		if (idBytes)
			idBytes.fill(0);
	}

	if (qrBtn) {
		qrBtn.style.display = state.link ? 'inline-block' : 'none';
		qrBtn.textContent = state.qrVisible ? 'Hide QR' : 'Generate QR';
	}
	updateQr();
}

function getOrigin()
{
	const el = $('host');
	const raw = (el.value.length > 6 ? el.value :
					   'https://local.tanuki-gecko.ts.net')
			    .trim();
	if (!raw)
		throw new Error('Service origin is empty');
	let parsed;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error('Invalid service origin URL');
	}
	if (parsed.username || parsed.password) {
		throw new Error('Origin must not include credentials');
	}
	if ((parsed.pathname && parsed.pathname !== '/') || parsed.search ||
	    parsed.hash) {
		throw new Error(
			'Origin must not include path, query, or fragment');
	}
	const isLocal = parsed.hostname === 'localhost' ||
			parsed.hostname === '127.0.0.1' ||
			parsed.hostname === '::1';
	if (parsed.protocol !== 'https:' && !isLocal) {
		throw new Error('Service origin must use https://');
	}
	const origin = parsed.origin;
	if (el && el.value !== origin) {
		el.value = origin;
	}
	return origin;
}

function base64UrlEncode(bytes)
{
	if (!(bytes instanceof Uint8Array))
		throw new TypeError('Expected Uint8Array');
	let bin = '';
	for (let i = 0; i < bytes.length; i++)
		bin += String.fromCharCode(bytes[i]);
	return btoa(bin)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/g, '');
}

function base64UrlDecode(str)
{
	try {
		const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
		const pad = normalized.length % 4;
		const padded = normalized + (pad ? '===='.slice(pad) : '');
		const bin = atob(padded);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++)
			out[i] = bin.charCodeAt(i);
		return out;
	} catch (err) {
		throw new Error('Invalid base64 data');
	}
}

async function deriveIdFromKeyAndSalt(keyBytes, saltBytes)
{
	const hkdfKey = await crypto.subtle.importKey('raw', keyBytes, 'HKDF',
						      false, ['deriveBits']);
	const bytes = await crypto.subtle.deriveBits({
		name: 'HKDF',
		hash: HKDF_HASH,
		salt: saltBytes,
		info: HKDF_INFO_ID
	},
						     hkdfKey, ID_SIZE * 8);
	return new Uint8Array(bytes);
}

async function derivePasswordKey(password, saltBytes, usages)
{
	const passwordBytes = encoder.encode(password);
	let keyMaterial;
	try {
		keyMaterial = await crypto.subtle.importKey(
			'raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
	} finally {
		passwordBytes.fill(0);
	}
	const key = await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: saltBytes,
			iterations: PBKDF2_ITERATIONS,
			hash: PBKDF2_HASH,
		},
		keyMaterial, { name: 'AES-GCM', length: KEY_SIZE * 8 }, false,
		usages);
	return key;
}

function parseLocationHash(input)
{
	if (!input)
		return null;
	let raw = input.trim();
	try {
		const maybeUrl = new URL(raw);
		raw = maybeUrl.hash || '';
	} catch {
		// not a URL; continue
	}
	if (raw.startsWith('#'))
		raw = raw.slice(1);
	const hashIndex = raw.indexOf('#');
	if (hashIndex >= 0)
		raw = raw.slice(hashIndex + 1);
	raw = raw.replace(/^\/+/, '');

	const parts = raw.split('/');
	if (parts.length !== 2)
		return null;
	let idPart = parts[0].trim();
	let keyPart = parts[1].trim();
	if (!idPart || !keyPart)
		return null;

	if (!ID_REGEX.test(idPart) || !keyPart)
		return null;
	return { id: idPart, bK: keyPart };
}

async function sendSecret(autoCopy = false)
{
	setStatus('');
	clearPendingSecret();
	lockTextarea(true)
	let keyBytes = null;
	let nonce = null;
	let salt = null;
	let idBytes = null;
	let payload = null;
	let taggedPayload = null;
	let ciphertext = null;
	let blob = null;
	let idBase64Url = null;
	try {
		const origin = getOrigin();
		const textField = $('text');
		const passwordInput = $('optionalPassword');
		const passwordValue = passwordInput.value;
		const hasPassword = typeof passwordValue === 'string' &&
				    passwordValue.length > 0;
		payload = encoder.encode(textField.value);
		// Generate random bytes
		keyBytes = crypto.getRandomValues(new Uint8Array(KEY_SIZE));
		nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
		salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
		// Construct an ID
		idBytes = await deriveIdFromKeyAndSalt(keyBytes, salt);
		idBase64Url = base64UrlEncode(idBytes);
		// Form aad
		const aad = encoder.encode('id=' + idBase64Url);
		if (hasPassword) {
			// Get the Pk
			const passwordKey = await derivePasswordKey(
				passwordValue, salt, ['encrypt']);
			const wrappedBuffer = await crypto.subtle.encrypt(
				{
					name: 'AES-GCM',
					iv: nonce,
					additionalData: aad
				},
				passwordKey, payload);
			payload.fill(0);
			payload = new Uint8Array(wrappedBuffer);
		}
		const tagBytes = hasPassword ? BLOB_TYPE_PASSWORD :
					       BLOB_TYPE_TEXT;
		taggedPayload = new Uint8Array(BLOB_TYPE_SIZE + payload.length);
		// Add tag
		taggedPayload.set(tagBytes, 0);
		taggedPayload.set(payload, BLOB_TYPE_SIZE);
		// Make K from bytes
		const aesKey = await crypto.subtle.importKey(
			'raw', keyBytes,
			{ name: 'AES-GCM', length: KEY_SIZE * 8 }, false,
			['encrypt']);
		// Encrypt
		ciphertext = new Uint8Array(await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv: nonce, additionalData: aad },
			aesKey, taggedPayload));

		taggedPayload.fill(0);
		taggedPayload = null;

		payload.fill(0);
		payload = null;

		// Construct the blob to send
		// TODO: optimize?
		blob = new Uint8Array(nonce.length + salt.length +
				      ciphertext.length);
		// Pack N \\ S \\ ct
		blob.set(nonce, 0);
		blob.set(salt, nonce.length);
		blob.set(ciphertext, nonce.length + salt.length);
		if (blob.length > BLOB_SIZE_MAX) {
			setStatus('Secret is too large. Maximum size is 1 MiB.',
				  false);
			return;
		}
		const url = normalizeOrigin(origin) + '/blob/' +
			    bytesToHex(idBytes);
		// Send the data
		const res = await fetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/octet-stream' },
			body: blob,
		});
		if (!res.ok) {
			const t = await safeText(res);
			throw new Error(`POST ${url} ${res.status}: ${
				t || res.statusText}`);
		} else {
			// Clear the password
			// TODO: Ok?
			passwordInput.value = '';
		}

		// === Decryption link ===
		const keyBase64Url = base64UrlEncode(keyBytes);
		setLink(origin, idBase64Url, keyBase64Url);
		const passwordNote =
			hasPassword ?
				' This secret requires the password you set during creation.' :
				'';
		if (autoCopy && state.link) {
			try {
				if (typeof navigator === 'undefined' ||
				    !navigator.clipboard ||
				    typeof navigator.clipboard.writeText !==
					    'function')
					throw new Error(
						'Clipboard API unavailable');
				await navigator.clipboard.writeText(state.link);
				setStatus(
					'Secret stored and the share link was copied to your clipboard automatically.' +
						passwordNote,
					true);
			} catch (copyErr) {
				console.error(copyErr);
				setStatus(
					'Secret stored, but automatic link copy failed. Use the copy button above.' +
						passwordNote,
					true);
			}
		} else {
			setStatus('Secret stored. Share the generated link.' +
					  passwordNote,
				  true);
		}
	} catch (err) {
		console.error(err);
		setStatus(err.message || String(err));
	} finally {
		if (payload)
			payload.fill(0);
		if (taggedPayload)
			taggedPayload.fill(0);
		if (ciphertext)
			ciphertext.fill(0);
		if (blob)
			blob.fill(0);
		if (keyBytes)
			keyBytes.fill(0);
		if (nonce)
			nonce.fill(0);
		if (salt)
			salt.fill(0);
		if (idBytes)
			idBytes.fill(0);
	}
	lockTextarea(false);
}

async function copyLink()
{
	try {
		if (!state.link) {
			setStatus('No link available to copy.', false);
			return;
		}
		await navigator.clipboard.writeText(state.link);
		setStatus('Link copied to clipboard.', true);
		setTimeout(() => {
			if (state.link)
				setStatus('');
		}, 1200);
	} catch (e) {
		setStatus('Could not copy link: ' + (e.message || e), false);
	}
}

async function safeText(res)
{
	try {
		return await res.text();
	} catch {
		return '';
	}
}

async function tryToReceiveSecret()
{
	const info = parseLocationHash(window.location.hash || '');
	if (!info)
		return;
	clearLocationHash();
	clearPendingSecret();
	lockTextarea(true);
	let keyBytes = null;
	let buf = null;
	let plaintextBytes = null;
	let idBytes = null;
	let derivedIdBytes = null;
	try {
		const origin = getOrigin();
		keyBytes = base64UrlDecode(info.bK);
		if (keyBytes.length !== KEY_SIZE)
			throw new Error('Key length mismatch');
		idBytes = base64UrlDecode(info.id);
		if (!idBytes || idBytes.length !== ID_SIZE)
			throw new Error('ID length mismatch');
		setStatus('Fetching secret…');
		const url = normalizeOrigin(origin) + '/blob/' +
			    bytesToHex(idBytes);
		// Fetch the blob
		const res = await fetch(url);
		if (!res.ok) {
			const t = await safeText(res);
			throw new Error(`GET ${url} ${res.status}: ${
				t || res.statusText}`);
		}
		buf = new Uint8Array(await res.arrayBuffer());
		// Check its size
		// TODO: count better
		if (buf.length <= NONCE_SIZE + SALT_SIZE + BLOB_TYPE_SIZE)
			throw new Error('Blob is too small');

		// Unpack N, S and ct
		const nonce = buf.subarray(0, NONCE_SIZE);
		const salt = buf.subarray(NONCE_SIZE, NONCE_SIZE + SALT_SIZE);
		const ct = buf.subarray(NONCE_SIZE + SALT_SIZE);

		derivedIdBytes = await deriveIdFromKeyAndSalt(keyBytes, salt);
		// Check the id
		if (!equal16B(derivedIdBytes, idBytes)) {
			const derivedIdBase64Url =
				base64UrlEncode(derivedIdBytes);
			const err = new Error(`ID mismatch: derived ID' (${
				derivedIdBase64Url}) !== provided ID (${
				info.id}).`);
			err.name = 'IdMismatchError';
			err.derivedId = derivedIdBase64Url;
			err.providedId = info.id;
			throw err;
		}

		// Construct K
		const aesKey = await crypto.subtle.importKey(
			'raw', keyBytes,
			{ name: 'AES-GCM', length: KEY_SIZE * 8 }, false,
			['decrypt']);
		const aad = encoder.encode('id=' + info.id);
		// Decrypt
		plaintextBytes = new Uint8Array(await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: nonce, additionalData: aad },
			aesKey, ct));
		if (plaintextBytes.length < BLOB_TYPE_SIZE)
			throw new Error('Decrypted payload missing type tag');
		// Unpack type tag
		const blobTypeTagValue = (plaintextBytes[0] << 8) |
					 plaintextBytes[1];
		const passwordProtected = blobTypeTagValue ===
					  BLOB_TYPE_PASSWORD_VALUE;
		if (!passwordProtected &&
		    blobTypeTagValue !== BLOB_TYPE_TEXT_VALUE)
			throw new Error('Unsupported blob type');
		const payloadBytes = plaintextBytes.subarray(BLOB_TYPE_SIZE);
		if (passwordProtected) {
			const nonceCopy = cloneBytes(nonce);
			const saltCopy = cloneBytes(salt);
			const ciphertextCopy = cloneBytes(payloadBytes);
			if (!nonceCopy || !saltCopy || !ciphertextCopy)
				throw new Error(
					'Failed to prepare password protected payload');
			state.pendingSecret = {
				id: info.id,
				nonce: nonceCopy,
				salt: saltCopy,
				ciphertext: ciphertextCopy,
			};
			plaintextBytes.fill(0);
			plaintextBytes = null;
			setDecryptionCardVisible(true);
			setStatus('Password required to decrypt this secret.',
				  false);
			const passwordField = $('decryptionPassword');
			if (passwordField) {
				passwordField.value = '';
				passwordField.focus();
			}
			return;
		}
		const textField = $('text');
		textField.value = decoder.decode(payloadBytes);
		textField.dispatchEvent(new Event('input', { bubbles: true }));
		setStatus('Secret retrieved and decrypted.', true);
	} catch (err) {
		console.error(err);
		setDecryptionCardVisible(false);
		setStatus(err.message || String(err));
		clearPendingSecret();
	} finally {
		if (plaintextBytes)
			plaintextBytes.fill(0);
		if (keyBytes)
			keyBytes.fill(0);
		if (idBytes)
			idBytes.fill(0);
		if (derivedIdBytes)
			derivedIdBytes.fill(0);
		if (buf)
			buf.fill(0);
		lockTextarea(false);
	}
}

async function decryptPendingSecretWithPassword()
{
	const pending = state.pendingSecret;
	if (!pending || !pending.ciphertext) {
		setStatus('No secret waiting for password decryption.', false);
		return;
	}
	const passwordField = $('decryptionPassword');
	const passwordValue = passwordField.value;
	if (!passwordValue) {
		setStatus('Enter the password to decrypt this secret.', false);
		passwordField.focus();
		return;
	}
	let plaintextBytes = null;
	let decrypted = false;
	try {
		setStatus('Decrypting secret with provided password…');
		// Construct Pk
		const passwordKey = await derivePasswordKey(
			passwordValue, pending.salt, ['decrypt']);
		const aad = encoder.encode('id=' + pending.id);
		// Decrypt
		plaintextBytes = new Uint8Array(await crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv: pending.nonce,
				additionalData: aad
			},
			passwordKey, pending.ciphertext));
		const textField = $('text');
		textField.value = decoder.decode(plaintextBytes);
		textField.dispatchEvent(new Event('input', { bubbles: true }));
		passwordField.value = '';
		setStatus('Secret decrypted with the provided password.', true);
		setDecryptionCardVisible(false);
		decrypted = true;
	} catch (err) {
		console.error(err);
		setStatus('Could not decrypt with that password.', false);
		passwordField.select();
		passwordField.focus();
	} finally {
		if (decrypted)
			clearPendingSecret();
		if (plaintextBytes)
			plaintextBytes.fill(0);
	}
}

const hostInput = $('host');
if (hostInput) {
	try {
		const current = window.location.origin;
		if (current && current !== 'null')
			hostInput.value = current;
	} catch (_) {
		// Ignore environments without window.location.origin support.
	}
}

$('btnGetLink').addEventListener('click', () => { void sendSecret(false); });
$('btnCopyLink').addEventListener('click', copyLink);
const optionalPasswordField = $('optionalPassword');
const textArea = $('text');
if (state.originalPlaceholder === null) {
	const initial = textArea.getAttribute('placeholder');
	state.originalPlaceholder = typeof initial === 'string' ? initial : '';
}
textArea.addEventListener('keydown', (event) => {
	const modifierPressed = isMacLike ? event.metaKey : event.ctrlKey;
	if (event.key === 'Enter' && modifierPressed) {
		if (!event.repeat)
			void sendSecret(true);
		event.preventDefault();
	}
});
optionalPasswordField.addEventListener('keydown', (event) => {
	const modifierPressed = isMacLike ? event.metaKey : event.ctrlKey;
	if (event.key === 'Enter' && modifierPressed) {
		if (!event.repeat)
			void sendSecret(true);
		event.preventDefault();
	}
});
const decryptBtn = $('decryptBtn');
decryptBtn.addEventListener('click',
			    () => { void decryptPendingSecretWithPassword(); });
const passwordField = $('decryptionPassword');
passwordField.addEventListener('keydown', (event) => {
	if (event.key === 'Enter') {
		event.preventDefault();
		void decryptPendingSecretWithPassword();
	}
});
const qrButton = $('btnGenerateQr');
qrButton.addEventListener('click', () => {
	if (!state.link) {
		setStatus('Generate a link first.');
		return;
	}
	state.qrVisible = !state.qrVisible;
	updateQr();
	qrButton.textContent = state.qrVisible ? 'Hide QR' : 'Generate QR';
	if (state.qrVisible)
		setStatus('QR code generated.', true);
});
const closeStatusBtn = $('closeStatus');
closeStatusBtn.addEventListener('click', () => { setStatus(''); });
$('host').addEventListener('change', () => {
	if (!state.id || !state.bK)
		return;
	try {
		const origin = getOrigin();
		setLink(origin, state.id, state.bK);
	} catch {
		// keep previously generated link until origin is valid again
	}
});

document.addEventListener('DOMContentLoaded', function() {
	const textarea = document.getElementById('text');
	const navToggle = document.querySelector('.nav-toggle');
	const navLinks = document.querySelector('.nav-links');

	if (textarea) {
		const charCount = document.createElement('div');
		const encoder = typeof TextEncoder === 'function' ?
					new TextEncoder() :
					null;
		const maxBytes = BLOB_SIZE_MAX - 100; // TODO: count better
		const maxKiBLabel = (maxBytes / 1024).toFixed(2);
		const toKiB = (bytes) => (bytes / 1024).toFixed(2);

		charCount.classList.add('char-counter');
		textarea.parentNode.appendChild(charCount);

		const updateCount = () => {
			const value = textarea.value || '';
			const sizeBytes = encoder ?
						  encoder.encode(value).length :
						  value.length;
			const usageKiB = toKiB(sizeBytes);

			charCount.textContent =
				maxKiBLabel ?
					`${usageKiB} of ${maxKiBLabel} KiB` :
					`${usageKiB} KiB`;
			charCount.classList.remove('warning', 'danger');

			if (maxBytes) {
				const usageRatio = sizeBytes / maxBytes;
				if (usageRatio > 0.9) {
					charCount.classList.add('danger');
				} else if (usageRatio > 0.8) {
					charCount.classList.add('warning');
				}
			}
		};

		textarea.addEventListener('input', updateCount);
		updateCount();
	}

	if (navToggle && navLinks) {
		const closeNav = () => {
			if (!navLinks.classList.contains('is-open')) {
				return;
			}
			navLinks.classList.remove('is-open');
			navToggle.classList.remove('is-active');
		};

		navToggle.addEventListener('click', () => {
			const isOpen = navLinks.classList.toggle('is-open');
			navToggle.classList.toggle('is-active', isOpen);
		});

		navLinks.addEventListener('click', (event) => {
			if (event.target.classList.contains('nav-link')) {
				closeNav();
			}
		});

		document.addEventListener('click', (event) => {
			if (!navLinks.contains(event.target) &&
			    !navToggle.contains(event.target)) {
				closeNav();
			}
		});

		window.addEventListener('resize', () => {
			if (window.innerWidth > 768) {
				navLinks.classList.remove('is-open');
				navToggle.classList.remove('is-active');
			}
		});
	}
});
tryToReceiveSecret();
