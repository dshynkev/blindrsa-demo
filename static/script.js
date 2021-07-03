// 01 -- DOM and storage utilities

// writeSpan writes a string into a <span>-like elemen with given id.
function writeSpan(id, value) {
  const elem = document.getElementById(id);
  elem.innerText = value;
}

// writeSpan reads the contents of a <span>-like elemen with given id.
function readSpan(id) {
  const elem = document.getElementById(id);
  return elem.innerText;
}

// writeAll writes a string to DOM for display and to localStorage.
function writeAll(id, value) {
  writeSpan(id, value);
  localStorage.setItem(id, value);
}

// freezeButtons disables all buttons except saveButton.
function freezeButtons() {
  const buttons = document.getElementsByTagName("button");
  for (button of buttons) {
    if (button.id !== "saveButton") {
      button.disabled = true;
    }
  }
}

// 02 -- string manipulation

// hexByte turns one byte into a two-character hex string.
function hexByte(b) {
  if (b < 0x10) {
    return "0" + b.toString(16);
  } else {
    return b.toString(16);
  }
}

// hexlify turns a Uint8Array into a hex string.
function hexlify(array) {
  // Array.from is necessary in case array is typed.
  // For example, Uint8Array.map requires returns to be uint8.
  return Array.from(array, hexByte).join("");
}

// unhexlify turns a hex string into a Uint8Array.
function unhexlify(string) {
  function* pairwise(seq) {
    for (let i = 0; i < seq.length; i += 2) {
      yield seq[i] + seq[i + 1];
    }
  }
  return Uint8Array.from(pairwise(string), x => Number.parseInt(x, 16));
}

// 03 -- cryptography

// modpow computes (a^e mod n) efficiently.
function modpow(a, e, n) {
  let result = 1n;
  while (e > 0) {
    if (e & 1n) {
      result = (result * a) % n;
    }
    e >>= 1n;
    a = (a ** 2n) % n;
  }
  return result;
}

// modinv computes (a^(-1) mod n) efficiently.
function modinv(a, n) {
  function egcd(m, n) {
    let x = 0n, y = 1n, u = 1n, v = 0n;
    while (m !== 0n) {
      const q = n / m;
      const r = n % m;
      const s = x - (u * q);
      const t = y - (v * q);
      n = m; m = r; x = u; y = v; u = s; v = t;
    }
    return {g: n, x: x, y: y};
  }

  const {g, x, y} = egcd(a, n);
  if (g !== 1n) {
    throw new RangeError("not invertible");
  } else {
    return (x + n) % n; // x may be negative
  }
}

// 04 -- scripting the page

async function fetchPublicKey() {
  const pkey = await fetch("/pkey").then(response => response.json());
  writeAll("public-exponent", pkey.e);
  writeAll("modulus", pkey.n);
}

async function generateToken() {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  writeAll("token", hexlify(id));
}

async function hashToken() {
  const id = unhexlify(readSpan("token"));

  const digest = await crypto.subtle.digest("SHA-512", id.buffer);
  // digest is an ArrayBuffer, thus cannot be directly hexlified.
  const digestString = hexlify(new Uint8Array(digest));

  writeAll("token-hash", digestString);
}

async function generateBlindingOffset() {
  const offset = new Uint8Array(256);
  crypto.getRandomValues(offset);

  writeAll("blinding-offset", hexlify(offset));
}


async function blindMessage() {
  const m = BigInt("0x" + readSpan("token-hash"));
  const r = BigInt("0x" + readSpan("blinding-offset"));
  const e = BigInt("0x" + readSpan("public-exponent"));
  const n = BigInt("0x" + readSpan("modulus"));

  const mr = (m * modpow(r, e, n)) % n;
  writeAll("blinded-message", mr.toString(16));
}

async function signBlindedMessage() {
  const mr = readSpan("blinded-message");

  const {s} = await fetch("/sign", {"method": "POST", body: JSON.stringify({m: mr})})
    .then(response => response.json());
  writeAll("blind-signature", s);

  // From this point on, we will not get another signature.
  freezeButtons();
}

async function unblindSignature() {
  const sb = BigInt("0x" + readSpan("blind-signature"));
  const r = BigInt("0x" + readSpan("blinding-offset"));
  const n = BigInt("0x" + readSpan("modulus"));

  const rinv = modinv(r, n);
  const s = sb * rinv % n;

  writeAll("signature", s.toString(16));
}

async function verifySignature() {
  const m = BigInt("0x" + readSpan("token-hash"));
  const s = BigInt("0x" + readSpan("signature"));
  const e = BigInt("0x" + readSpan("public-exponent"));
  const n = BigInt("0x" + readSpan("modulus"));

  const v = modpow(s, e, n);

  if (v === m) {
    writeSpan("verified", "✔ Valid signature");
  } else {
    writeSpan("verified", "✗ Invalid signature");
  }
}

async function saveCredentials() {
  const token = readSpan("token");
  const signature = readSpan("signature");

  const bundle = {token, signature};
  const blob = new Blob([JSON.stringify(bundle)], {type: "application/json"});

  const href = URL.createObjectURL(blob);

  // Here we do a dance with creating an <a> element
  // and clicking on it instead of simply setting window.location.
  // This is so that a download is initiated instead of the JSON content
  // being simply displayed in the browser.
  // Also, this lets us specify a suggested file name.

  const elem = document.createElement("a");
  elem.href = href;
  elem.download = "uwcs22-credentials.json"

  document.body.appendChild(elem);
  elem.click();
  document.body.removeChild(elem);

  URL.revokeObjectURL(href);
}


async function hashAndBlind() {
  await hashToken();
  await generateBlindingOffset();
  await blindMessage();
}

async function signAndUnblind() {
  await signBlindedMessage();
  await unblindSignature();
  await verifySignature();
}

// When the page loads (we are guaranteed to see this as the script loads
// synchronously in <head>), fill all the display fields from values in storage.
addEventListener("DOMContentLoaded", function() {
  const fields = document.getElementsByClassName("display");
  for (field of fields) {
    const storedValue = localStorage.getItem(field.id);
    if (storedValue !== null) {
      field.innerText = storedValue;
      // If the signature is already set, prevent overwriting.
      if (field.id === "signature") {
        verifySignature();
        freezeButtons();
      }
    }
  }
});
