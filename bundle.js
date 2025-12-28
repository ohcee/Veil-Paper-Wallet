(() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __esm = (fn, res) => function __init() {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  };
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };

  // node_modules/@noble/secp256k1/index.js
  var secp256k1_CURVE, P, N, Gx, Gy, _b, L, L2, lengths, captureTrace, err, isBig, isStr, isBytes, abytes, u8n, padh, bytesToHex, C, _ch, hexToBytes, cr, concatBytes, randomBytes, big, arange, M, modN, invert, apoint, koblitz, FpIsValid, FpIsValidNot0, FnIsValidNot0, isEven, u8of, getPrefix, lift_x, Point, G, I, bytesToNumBE, sliceBytesNumBE, B256, numTo32b, secretKeyToScalar, getPublicKey, NULL, byte0, byte1, randomSecretKey, createKeygen, keygen, extpubSchnorr, pubSchnorr, keygenSchnorr, W, scalarBits, pwindows, pwindowSize, precompute, Gpows, ctneg, wNAF;
  var init_secp256k1 = __esm({
    "node_modules/@noble/secp256k1/index.js"() {
      secp256k1_CURVE = {
        p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
        n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
        h: 1n,
        a: 0n,
        b: 7n,
        Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
        Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
      };
      ({ p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE);
      L = 32;
      L2 = 64;
      lengths = {
        publicKey: L + 1,
        publicKeyUncompressed: L2 + 1,
        signature: L2,
        seed: L + L / 2
      };
      captureTrace = (...args) => {
        if ("captureStackTrace" in Error && typeof Error.captureStackTrace === "function") {
          Error.captureStackTrace(...args);
        }
      };
      err = (message = "") => {
        const e = new Error(message);
        captureTrace(e, err);
        throw e;
      };
      isBig = (n) => typeof n === "bigint";
      isStr = (s) => typeof s === "string";
      isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
      abytes = (value, length, title = "") => {
        const bytes = isBytes(value);
        const len = value?.length;
        const needsLen = length !== void 0;
        if (!bytes || needsLen && len !== length) {
          const prefix = title && `"${title}" `;
          const ofLen = needsLen ? ` of length ${length}` : "";
          const got = bytes ? `length=${len}` : `type=${typeof value}`;
          err(prefix + "expected Uint8Array" + ofLen + ", got " + got);
        }
        return value;
      };
      u8n = (len) => new Uint8Array(len);
      padh = (n, pad) => n.toString(16).padStart(pad, "0");
      bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
      C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
      _ch = (ch) => {
        if (ch >= C._0 && ch <= C._9)
          return ch - C._0;
        if (ch >= C.A && ch <= C.F)
          return ch - (C.A - 10);
        if (ch >= C.a && ch <= C.f)
          return ch - (C.a - 10);
        return;
      };
      hexToBytes = (hex) => {
        const e = "hex invalid";
        if (!isStr(hex))
          return err(e);
        const hl = hex.length;
        const al = hl / 2;
        if (hl % 2)
          return err(e);
        const array = u8n(al);
        for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
          const n1 = _ch(hex.charCodeAt(hi));
          const n2 = _ch(hex.charCodeAt(hi + 1));
          if (n1 === void 0 || n2 === void 0)
            return err(e);
          array[ai] = n1 * 16 + n2;
        }
        return array;
      };
      cr = () => globalThis?.crypto;
      concatBytes = (...arrs) => {
        const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
        let pad = 0;
        arrs.forEach((a) => {
          r.set(a, pad);
          pad += a.length;
        });
        return r;
      };
      randomBytes = (len = L) => {
        const c = cr();
        return c.getRandomValues(u8n(len));
      };
      big = BigInt;
      arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
      M = (a, b = P) => {
        const r = a % b;
        return r >= 0n ? r : b + r;
      };
      modN = (a) => M(a, N);
      invert = (num, md) => {
        if (num === 0n || md <= 0n)
          err("no inverse n=" + num + " mod=" + md);
        let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
        while (a !== 0n) {
          const q = b / a, r = b % a;
          const m = x - u * q, n = y - v * q;
          b = a, a = r, x = u, y = v, u = m, v = n;
        }
        return b === 1n ? M(x, md) : err("no inverse");
      };
      apoint = (p) => p instanceof Point ? p : err("Point expected");
      koblitz = (x) => M(M(x * x) * x + _b);
      FpIsValid = (n) => arange(n, 0n, P);
      FpIsValidNot0 = (n) => arange(n, 1n, P);
      FnIsValidNot0 = (n) => arange(n, 1n, N);
      isEven = (y) => (y & 1n) === 0n;
      u8of = (n) => Uint8Array.of(n);
      getPrefix = (y) => u8of(isEven(y) ? 2 : 3);
      lift_x = (x) => {
        const c = koblitz(FpIsValidNot0(x));
        let r = 1n;
        for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
          if (e & 1n)
            r = r * num % P;
          num = num * num % P;
        }
        return M(r * r) === c ? r : err("sqrt invalid");
      };
      Point = class _Point {
        static BASE;
        static ZERO;
        X;
        Y;
        Z;
        constructor(X, Y, Z) {
          this.X = FpIsValid(X);
          this.Y = FpIsValidNot0(Y);
          this.Z = FpIsValid(Z);
          Object.freeze(this);
        }
        static CURVE() {
          return secp256k1_CURVE;
        }
        /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
        static fromAffine(ap) {
          const { x, y } = ap;
          return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
        }
        /** Convert Uint8Array or hex string to Point. */
        static fromBytes(bytes) {
          abytes(bytes);
          const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
          let p = void 0;
          const length = bytes.length;
          const head = bytes[0];
          const tail = bytes.subarray(1);
          const x = sliceBytesNumBE(tail, 0, L);
          if (length === comp && (head === 2 || head === 3)) {
            let y = lift_x(x);
            const evenY = isEven(y);
            const evenH = isEven(big(head));
            if (evenH !== evenY)
              y = M(-y);
            p = new _Point(x, y, 1n);
          }
          if (length === uncomp && head === 4)
            p = new _Point(x, sliceBytesNumBE(tail, L, L2), 1n);
          return p ? p.assertValidity() : err("bad point: not on curve");
        }
        static fromHex(hex) {
          return _Point.fromBytes(hexToBytes(hex));
        }
        get x() {
          return this.toAffine().x;
        }
        get y() {
          return this.toAffine().y;
        }
        /** Equality check: compare points P&Q. */
        equals(other) {
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
          const X1Z2 = M(X1 * Z2);
          const X2Z1 = M(X2 * Z1);
          const Y1Z2 = M(Y1 * Z2);
          const Y2Z1 = M(Y2 * Z1);
          return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
        }
        is0() {
          return this.equals(I);
        }
        /** Flip point over y coordinate. */
        negate() {
          return new _Point(this.X, M(-this.Y), this.Z);
        }
        /** Point doubling: P+P, complete formula. */
        double() {
          return this.add(this);
        }
        /**
         * Point addition: P+Q, complete, exception-free formula
         * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
         * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
         */
        // prettier-ignore
        add(other) {
          const { X: X1, Y: Y1, Z: Z1 } = this;
          const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
          const a = 0n;
          const b = _b;
          let X3 = 0n, Y3 = 0n, Z3 = 0n;
          const b3 = M(b * 3n);
          let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
          let t4 = M(X2 + Y2);
          t3 = M(t3 * t4);
          t4 = M(t0 + t1);
          t3 = M(t3 - t4);
          t4 = M(X1 + Z1);
          let t5 = M(X2 + Z2);
          t4 = M(t4 * t5);
          t5 = M(t0 + t2);
          t4 = M(t4 - t5);
          t5 = M(Y1 + Z1);
          X3 = M(Y2 + Z2);
          t5 = M(t5 * X3);
          X3 = M(t1 + t2);
          t5 = M(t5 - X3);
          Z3 = M(a * t4);
          X3 = M(b3 * t2);
          Z3 = M(X3 + Z3);
          X3 = M(t1 - Z3);
          Z3 = M(t1 + Z3);
          Y3 = M(X3 * Z3);
          t1 = M(t0 + t0);
          t1 = M(t1 + t0);
          t2 = M(a * t2);
          t4 = M(b3 * t4);
          t1 = M(t1 + t2);
          t2 = M(t0 - t2);
          t2 = M(a * t2);
          t4 = M(t4 + t2);
          t0 = M(t1 * t4);
          Y3 = M(Y3 + t0);
          t0 = M(t5 * t4);
          X3 = M(t3 * X3);
          X3 = M(X3 - t0);
          t0 = M(t3 * t1);
          Z3 = M(t5 * Z3);
          Z3 = M(Z3 + t0);
          return new _Point(X3, Y3, Z3);
        }
        subtract(other) {
          return this.add(apoint(other).negate());
        }
        /**
         * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
         * Uses {@link wNAF} for base point.
         * Uses fake point to mitigate side-channel leakage.
         * @param n scalar by which point is multiplied
         * @param safe safe mode guards against timing attacks; unsafe mode is faster
         */
        multiply(n, safe = true) {
          if (!safe && n === 0n)
            return I;
          FnIsValidNot0(n);
          if (n === 1n)
            return this;
          if (this.equals(G))
            return wNAF(n).p;
          let p = I;
          let f = G;
          for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
            if (n & 1n)
              p = p.add(d);
            else if (safe)
              f = f.add(d);
          }
          return p;
        }
        multiplyUnsafe(scalar) {
          return this.multiply(scalar, false);
        }
        /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
        toAffine() {
          const { X: x, Y: y, Z: z } = this;
          if (this.equals(I))
            return { x: 0n, y: 0n };
          if (z === 1n)
            return { x, y };
          const iz = invert(z, P);
          if (M(z * iz) !== 1n)
            err("inverse invalid");
          return { x: M(x * iz), y: M(y * iz) };
        }
        /** Checks if the point is valid and on-curve. */
        assertValidity() {
          const { x, y } = this.toAffine();
          FpIsValidNot0(x);
          FpIsValidNot0(y);
          return M(y * y) === koblitz(x) ? this : err("bad point: not on curve");
        }
        /** Converts point to 33/65-byte Uint8Array. */
        toBytes(isCompressed = true) {
          const { x, y } = this.assertValidity().toAffine();
          const x32b = numTo32b(x);
          if (isCompressed)
            return concatBytes(getPrefix(y), x32b);
          return concatBytes(u8of(4), x32b, numTo32b(y));
        }
        toHex(isCompressed) {
          return bytesToHex(this.toBytes(isCompressed));
        }
      };
      G = new Point(Gx, Gy, 1n);
      I = new Point(0n, 1n, 0n);
      Point.BASE = G;
      Point.ZERO = I;
      bytesToNumBE = (b) => big("0x" + (bytesToHex(b) || "0"));
      sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
      B256 = 2n ** 256n;
      numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
      secretKeyToScalar = (secretKey) => {
        const num = bytesToNumBE(abytes(secretKey, L, "secret key"));
        return arange(num, 1n, N, "invalid secret key: outside of range");
      };
      getPublicKey = (privKey, isCompressed = true) => {
        return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
      };
      NULL = u8n(0);
      byte0 = u8of(0);
      byte1 = u8of(1);
      randomSecretKey = (seed = randomBytes(lengths.seed)) => {
        abytes(seed);
        if (seed.length < lengths.seed || seed.length > 1024)
          err("expected 40-1024b");
        const num = M(bytesToNumBE(seed), N - 1n);
        return numTo32b(num + 1n);
      };
      createKeygen = (getPublicKey2) => (seed) => {
        const secretKey = randomSecretKey(seed);
        return { secretKey, publicKey: getPublicKey2(secretKey) };
      };
      keygen = createKeygen(getPublicKey);
      extpubSchnorr = (priv) => {
        const d_ = secretKeyToScalar(priv);
        const p = G.multiply(d_);
        const { x, y } = p.assertValidity().toAffine();
        const d = isEven(y) ? d_ : modN(-d_);
        const px = numTo32b(x);
        return { d, px };
      };
      pubSchnorr = (secretKey) => {
        return extpubSchnorr(secretKey).px;
      };
      keygenSchnorr = createKeygen(pubSchnorr);
      W = 8;
      scalarBits = 256;
      pwindows = Math.ceil(scalarBits / W) + 1;
      pwindowSize = 2 ** (W - 1);
      precompute = () => {
        const points = [];
        let p = G;
        let b = p;
        for (let w = 0; w < pwindows; w++) {
          b = p;
          points.push(b);
          for (let i = 1; i < pwindowSize; i++) {
            b = b.add(p);
            points.push(b);
          }
          p = b.double();
        }
        return points;
      };
      Gpows = void 0;
      ctneg = (cnd, p) => {
        const n = p.negate();
        return cnd ? n : p;
      };
      wNAF = (n) => {
        const comp = Gpows || (Gpows = precompute());
        let p = I;
        let f = G;
        const pow_2_w = 2 ** W;
        const maxNum = pow_2_w;
        const mask = big(pow_2_w - 1);
        const shiftBy = big(W);
        for (let w = 0; w < pwindows; w++) {
          let wbits = Number(n & mask);
          n >>= shiftBy;
          if (wbits > pwindowSize) {
            wbits -= maxNum;
            n += 1n;
          }
          const off = w * pwindowSize;
          const offF = off;
          const offP = off + Math.abs(wbits) - 1;
          const isEven2 = w % 2 !== 0;
          const isNeg = wbits < 0;
          if (wbits === 0) {
            f = f.add(ctneg(isEven2, comp[offF]));
          } else {
            p = p.add(ctneg(isNeg, comp[offP]));
          }
        }
        if (n !== 0n)
          err("invalid wnaf");
        return { p, f };
      };
    }
  });

  // node_modules/@noble/hashes/esm/utils.js
  function isBytes2(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function abytes2(b, ...lengths2) {
    if (!isBytes2(b))
      throw new Error("Uint8Array expected");
    if (lengths2.length > 0 && !lengths2.includes(b.length))
      throw new Error("Uint8Array expected of length " + lengths2 + ", got length=" + b.length);
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance) {
    abytes2(out);
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error("digestInto() expects output buffer of length at least " + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function rotl(word, shift) {
    return word << shift | word >>> 32 - shift >>> 0;
  }
  function utf8ToBytes(str) {
    if (typeof str !== "string")
      throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
  }
  function toBytes(data) {
    if (typeof data === "string")
      data = utf8ToBytes(data);
    abytes2(data);
    return data;
  }
  function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
  }
  var Hash;
  var init_utils = __esm({
    "node_modules/@noble/hashes/esm/utils.js"() {
      Hash = class {
      };
    }
  });

  // node_modules/@noble/hashes/esm/_md.js
  function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === "function")
      return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(4294967295);
    const wh = Number(value >> _32n & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
  }
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD, SHA256_IV;
  var init_md = __esm({
    "node_modules/@noble/hashes/esm/_md.js"() {
      init_utils();
      HashMD = class extends Hash {
        constructor(blockLen, outputLen, padOffset, isLE) {
          super();
          this.finished = false;
          this.length = 0;
          this.pos = 0;
          this.destroyed = false;
          this.blockLen = blockLen;
          this.outputLen = outputLen;
          this.padOffset = padOffset;
          this.isLE = isLE;
          this.buffer = new Uint8Array(blockLen);
          this.view = createView(this.buffer);
        }
        update(data) {
          aexists(this);
          data = toBytes(data);
          abytes2(data);
          const { view, buffer, blockLen } = this;
          const len = data.length;
          for (let pos = 0; pos < len; ) {
            const take = Math.min(blockLen - this.pos, len - pos);
            if (take === blockLen) {
              const dataView = createView(data);
              for (; blockLen <= len - pos; pos += blockLen)
                this.process(dataView, pos);
              continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
              this.process(view, 0);
              this.pos = 0;
            }
          }
          this.length += data.length;
          this.roundClean();
          return this;
        }
        digestInto(out) {
          aexists(this);
          aoutput(out, this);
          this.finished = true;
          const { buffer, view, blockLen, isLE } = this;
          let { pos } = this;
          buffer[pos++] = 128;
          clean(this.buffer.subarray(pos));
          if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
          }
          for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
          setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
          this.process(view, 0);
          const oview = createView(out);
          const len = this.outputLen;
          if (len % 4)
            throw new Error("_sha2: outputLen should be aligned to 32bit");
          const outLen = len / 4;
          const state = this.get();
          if (outLen > state.length)
            throw new Error("_sha2: outputLen bigger than state");
          for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
          const { buffer, outputLen } = this;
          this.digestInto(buffer);
          const res = buffer.slice(0, outputLen);
          this.destroy();
          return res;
        }
        _cloneInto(to) {
          to || (to = new this.constructor());
          to.set(...this.get());
          const { blockLen, buffer, length, finished, destroyed, pos } = this;
          to.destroyed = destroyed;
          to.finished = finished;
          to.length = length;
          to.pos = pos;
          if (length % blockLen)
            to.buffer.set(buffer);
          return to;
        }
        clone() {
          return this._cloneInto();
        }
      };
      SHA256_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        3144134277,
        1013904242,
        2773480762,
        1359893119,
        2600822924,
        528734635,
        1541459225
      ]);
    }
  });

  // node_modules/@noble/hashes/esm/sha2.js
  var SHA256_K, SHA256_W, SHA256, sha256;
  var init_sha2 = __esm({
    "node_modules/@noble/hashes/esm/sha2.js"() {
      init_md();
      init_utils();
      SHA256_K = /* @__PURE__ */ Uint32Array.from([
        1116352408,
        1899447441,
        3049323471,
        3921009573,
        961987163,
        1508970993,
        2453635748,
        2870763221,
        3624381080,
        310598401,
        607225278,
        1426881987,
        1925078388,
        2162078206,
        2614888103,
        3248222580,
        3835390401,
        4022224774,
        264347078,
        604807628,
        770255983,
        1249150122,
        1555081692,
        1996064986,
        2554220882,
        2821834349,
        2952996808,
        3210313671,
        3336571891,
        3584528711,
        113926993,
        338241895,
        666307205,
        773529912,
        1294757372,
        1396182291,
        1695183700,
        1986661051,
        2177026350,
        2456956037,
        2730485921,
        2820302411,
        3259730800,
        3345764771,
        3516065817,
        3600352804,
        4094571909,
        275423344,
        430227734,
        506948616,
        659060556,
        883997877,
        958139571,
        1322822218,
        1537002063,
        1747873779,
        1955562222,
        2024104815,
        2227730452,
        2361852424,
        2428436474,
        2756734187,
        3204031479,
        3329325298
      ]);
      SHA256_W = /* @__PURE__ */ new Uint32Array(64);
      SHA256 = class extends HashMD {
        constructor(outputLen = 32) {
          super(64, outputLen, 8, false);
          this.A = SHA256_IV[0] | 0;
          this.B = SHA256_IV[1] | 0;
          this.C = SHA256_IV[2] | 0;
          this.D = SHA256_IV[3] | 0;
          this.E = SHA256_IV[4] | 0;
          this.F = SHA256_IV[5] | 0;
          this.G = SHA256_IV[6] | 0;
          this.H = SHA256_IV[7] | 0;
        }
        get() {
          const { A, B, C: C2, D, E, F, G: G2, H } = this;
          return [A, B, C2, D, E, F, G2, H];
        }
        // prettier-ignore
        set(A, B, C2, D, E, F, G2, H) {
          this.A = A | 0;
          this.B = B | 0;
          this.C = C2 | 0;
          this.D = D | 0;
          this.E = E | 0;
          this.F = F | 0;
          this.G = G2 | 0;
          this.H = H | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
          for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
            SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
          }
          let { A, B, C: C2, D, E, F, G: G2, H } = this;
          for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = sigma0 + Maj(A, B, C2) | 0;
            H = G2;
            G2 = F;
            F = E;
            E = D + T1 | 0;
            D = C2;
            C2 = B;
            B = A;
            A = T1 + T2 | 0;
          }
          A = A + this.A | 0;
          B = B + this.B | 0;
          C2 = C2 + this.C | 0;
          D = D + this.D | 0;
          E = E + this.E | 0;
          F = F + this.F | 0;
          G2 = G2 + this.G | 0;
          H = H + this.H | 0;
          this.set(A, B, C2, D, E, F, G2, H);
        }
        roundClean() {
          clean(SHA256_W);
        }
        destroy() {
          this.set(0, 0, 0, 0, 0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
    }
  });

  // node_modules/@noble/hashes/esm/legacy.js
  function ripemd_f(group, x, y, z) {
    if (group === 0)
      return x ^ y ^ z;
    if (group === 1)
      return x & y | ~x & z;
    if (group === 2)
      return (x | ~y) ^ z;
    if (group === 3)
      return x & z | y & ~z;
    return x ^ (y | ~z);
  }
  var Rho160, Id160, Pi160, idxLR, idxL, idxR, shifts160, shiftsL160, shiftsR160, Kl160, Kr160, BUF_160, RIPEMD160, ripemd160;
  var init_legacy = __esm({
    "node_modules/@noble/hashes/esm/legacy.js"() {
      init_md();
      init_utils();
      Rho160 = /* @__PURE__ */ Uint8Array.from([
        7,
        4,
        13,
        1,
        10,
        6,
        15,
        3,
        12,
        0,
        9,
        5,
        2,
        14,
        11,
        8
      ]);
      Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
      Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
      idxLR = /* @__PURE__ */ (() => {
        const L3 = [Id160];
        const R = [Pi160];
        const res = [L3, R];
        for (let i = 0; i < 4; i++)
          for (let j of res)
            j.push(j[i].map((k) => Rho160[k]));
        return res;
      })();
      idxL = /* @__PURE__ */ (() => idxLR[0])();
      idxR = /* @__PURE__ */ (() => idxLR[1])();
      shifts160 = /* @__PURE__ */ [
        [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
        [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
        [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
        [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
        [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
      ].map((i) => Uint8Array.from(i));
      shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
      shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
      Kl160 = /* @__PURE__ */ Uint32Array.from([
        0,
        1518500249,
        1859775393,
        2400959708,
        2840853838
      ]);
      Kr160 = /* @__PURE__ */ Uint32Array.from([
        1352829926,
        1548603684,
        1836072691,
        2053994217,
        0
      ]);
      BUF_160 = /* @__PURE__ */ new Uint32Array(16);
      RIPEMD160 = class extends HashMD {
        constructor() {
          super(64, 20, 8, true);
          this.h0 = 1732584193 | 0;
          this.h1 = 4023233417 | 0;
          this.h2 = 2562383102 | 0;
          this.h3 = 271733878 | 0;
          this.h4 = 3285377520 | 0;
        }
        get() {
          const { h0, h1, h2, h3, h4 } = this;
          return [h0, h1, h2, h3, h4];
        }
        set(h0, h1, h2, h3, h4) {
          this.h0 = h0 | 0;
          this.h1 = h1 | 0;
          this.h2 = h2 | 0;
          this.h3 = h3 | 0;
          this.h4 = h4 | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            BUF_160[i] = view.getUint32(offset, true);
          let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr2 = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
          for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl160[group], hbr = Kr160[group];
            const rl = idxL[group], rr = idxR[group];
            const sl = shiftsL160[group], sr = shiftsR160[group];
            for (let i = 0; i < 16; i++) {
              const tl = rotl(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
              al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
            }
            for (let i = 0; i < 16; i++) {
              const tr = rotl(ar + ripemd_f(rGroup, br, cr2, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
              ar = er, er = dr, dr = rotl(cr2, 10) | 0, cr2 = br, br = tr;
            }
          }
          this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr2 | 0);
        }
        roundClean() {
          clean(BUF_160);
        }
        destroy() {
          this.destroyed = true;
          clean(this.buffer);
          this.set(0, 0, 0, 0, 0);
        }
      };
      ripemd160 = /* @__PURE__ */ createHasher(() => new RIPEMD160());
    }
  });

  // app.js
  var require_app = __commonJS({
    "app.js"() {
      init_secp256k1();
      init_sha2();
      init_legacy();
      function getParamValue(param) {
        const m = new RegExp("[?&]" + param + "=([^&;#]+)").exec(location.search);
        return m ? decodeURIComponent(m[1].replace(/\+/g, "%20")) : null;
      }
      var isTestNet = getParamValue("testnet") === "true";
      var NET = isTestNet ? { name: "testnet", hrp: "tv", wif: 239 } : { name: "mainnet", hrp: "bv", wif: 128 };
      function concatBytes2(...arrs) {
        const len = arrs.reduce((s, a) => s + a.length, 0);
        const out = new Uint8Array(len);
        let o = 0;
        for (const a of arrs) {
          out.set(a, o);
          o += a.length;
        }
        return out;
      }
      function utf8Bytes(s) {
        return new TextEncoder().encode(s);
      }
      var B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      function base58encode(bytes) {
        let x = 0n;
        for (const b of bytes) x = (x << 8n) + BigInt(b);
        let out = "";
        while (x > 0n) {
          const mod = x % 58n;
          out = B58_ALPH[Number(mod)] + out;
          x = x / 58n;
        }
        for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
        return out || "1";
      }
      var BECH32_ALPH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
      function bech32Polymod(values) {
        const GEN = [996825010, 642813549, 513874426, 1027748829, 705979059];
        let chk = 1;
        for (const v of values) {
          const top = chk >>> 25;
          chk = (chk & 33554431) << 5 ^ v;
          for (let i = 0; i < 5; i++) {
            if (top >>> i & 1) chk ^= GEN[i];
          }
        }
        return chk;
      }
      function bech32HrpExpand(hrp) {
        const ret = [];
        for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
        ret.push(0);
        for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
        return ret;
      }
      function bech32CreateChecksum(hrp, data) {
        const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        const mod = bech32Polymod(values) ^ 1;
        const ret = [];
        for (let p = 0; p < 6; p++) ret.push(mod >>> 5 * (5 - p) & 31);
        return ret;
      }
      function bech32Encode(hrp, data) {
        const combined = data.concat(bech32CreateChecksum(hrp, data));
        let s = hrp + "1";
        for (const d of combined) s += BECH32_ALPH[d];
        return s;
      }
      function convertBits(data, from, to, pad) {
        let acc = 0;
        let bits = 0;
        const ret = [];
        const maxv = (1 << to) - 1;
        for (const value of data) {
          if (value < 0 || value >> from !== 0) throw new Error("convertBits: invalid value");
          acc = acc << from | value;
          bits += from;
          while (bits >= to) {
            bits -= to;
            ret.push(acc >> bits & maxv);
          }
        }
        if (pad) {
          if (bits) ret.push(acc << to - bits & maxv);
        } else {
          if (bits >= from) throw new Error("convertBits: excess padding");
          if (acc << to - bits & maxv) throw new Error("convertBits: non-zero padding");
        }
        return ret;
      }
      function encodeWitnessV0Address(hrp, programBytes20) {
        if (programBytes20.length !== 20) throw new Error("P2WPKH program must be 20 bytes");
        const version = 0;
        const data = [version].concat(convertBits(programBytes20, 8, 5, true));
        return bech32Encode(hrp, data);
      }
      function hash160(bytes) {
        return ripemd160(sha256(bytes));
      }
      function wifFromPrivkey(priv32, wifPrefix) {
        if (priv32.length !== 32) throw new Error("privkey must be 32 bytes");
        const payload = concatBytes2(new Uint8Array([wifPrefix]), priv32, new Uint8Array([1]));
        const checksum = sha256(sha256(payload)).slice(0, 4);
        return base58encode(concatBytes2(payload, checksum));
      }
      function base58decode(str) {
        let x = 0n;
        for (const ch of str) {
          const v = B58_ALPH.indexOf(ch);
          if (v === -1) throw new Error("Invalid base58 character");
          x = x * 58n + BigInt(v);
        }
        let bytes = [];
        while (x > 0n) {
          bytes.push(Number(x & 0xffn));
          x >>= 8n;
        }
        bytes.reverse();
        for (let i = 0; i < str.length && str[i] === "1"; i++) bytes.unshift(0);
        return new Uint8Array(bytes);
      }
      function privFromWif(wif) {
        const raw = base58decode(wif);
        if (raw.length < 4 + 1 + 32) throw new Error("WIF too short");
        const body = raw.slice(0, -4);
        const chk = raw.slice(-4);
        const chk2 = sha256(sha256(body)).slice(0, 4);
        for (let i = 0; i < 4; i++) if (chk[i] !== chk2[i]) throw new Error("Bad WIF checksum");
        const prefix = body[0];
        const key = body.slice(1, 33);
        const hasComp = body.length === 34 && body[33] === 1;
        if (!hasComp) throw new Error("This tool expects compressed WIF (has trailing 0x01).");
        return { prefix, priv32: key };
      }
      var $ = (id) => document.getElementById(id);
      function setNetBadge() {
        $("netBadge").textContent = `Network: ${NET.name} (${NET.hrp}1\u2026 addresses)`;
      }
      setNetBadge();
      var seed = null;
      var progress = 0;
      var done = false;
      var TARGET = 220;
      function resetAll() {
        seed = null;
        progress = 0;
        done = false;
        $("entropyCard").style.display = "none";
        $("barFill").style.width = "0%";
        $("barText").textContent = "0%";
        $("outAddr").textContent = "\u2014";
        $("outWif").textContent = "\u2014";
        $("verifyWif").value = "";
        $("verifyOut").textContent = "";
      }
      function startEntropy() {
        resetAll();
        $("entropyCard").style.display = "block";
        const r = new Uint8Array(32);
        crypto.getRandomValues(r);
        seed = sha256(r);
        const box = $("entropyBox");
        const onMove = (evt) => {
          if (!seed || done) return;
          const x = Math.floor(evt.clientX || 0);
          const y = Math.floor(evt.clientY || 0);
          const t = Math.floor(performance.now());
          seed = sha256(concatBytes2(seed, utf8Bytes(`${x},${y},${t},${progress}`)));
          progress++;
          const pct = Math.min(100, Math.floor(progress / TARGET * 100));
          $("barFill").style.width = pct + "%";
          $("barText").textContent = pct + "%";
          if (progress >= TARGET) {
            done = true;
            box.removeEventListener("mousemove", onMove);
            $("outAddr").textContent = "Generating\u2026";
            $("outWif").textContent = "Generating\u2026";
            try {
              finishGenerate();
            } catch (e) {
              console.error(e);
              $("verifyOut").textContent = `Generate error: ${e?.message || e}`;
              $("outAddr").textContent = "ERROR";
              $("outWif").textContent = "ERROR";
              seed = null;
              progress = 0;
              done = false;
            }
          }
        };
        box.addEventListener("mousemove", onMove, { passive: true });
      }
      var SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
      function finishGenerate() {
        let priv = sha256(concatBytes2(seed, utf8Bytes("veil-basecoin-v1")));
        for (let i = 0; i < 1e3; i++) {
          if (isValidPrivkey32(priv)) break;
          priv = sha256(concatBytes2(priv, new Uint8Array([i & 255])));
        }
        if (!isValidPrivkey32(priv)) {
          throw new Error("Failed to derive a valid private key (unexpected).");
        }
        const pub = getPublicKey(priv, true);
        const pkh = hash160(pub);
        const addr = encodeWitnessV0Address(NET.hrp, pkh);
        const wif = wifFromPrivkey(priv, NET.wif);
        $("outAddr").textContent = addr;
        $("outWif").textContent = wif;
        $("entropyCard").style.display = "none";
        seed = null;
        progress = 0;
      }
      function isValidPrivkey32(priv) {
        if (!(priv instanceof Uint8Array) || priv.length !== 32) return false;
        let x = 0n;
        for (const b of priv) x = (x << 8n) + BigInt(b);
        return x > 0n && x < SECP_N;
      }
      function verifyWif() {
        const wif = $("verifyWif").value.trim();
        if (!wif) return;
        try {
          const { prefix, priv32 } = privFromWif(wif);
          const hrp = prefix === 239 ? "tv" : prefix === 128 ? "bv" : null;
          if (!hrp) throw new Error("WIF prefix not recognized for Veil (expected 0x80 or 0xEF).");
          const pub = getPublicKey(priv32, true);
          const pkh = hash160(pub);
          const addr = encodeWitnessV0Address(hrp, pkh);
          $("verifyOut").textContent = `Derived address: ${addr}`;
        } catch (e) {
          $("verifyOut").textContent = `Error: ${e.message}`;
        }
      }
      $("btnStart").addEventListener("click", startEntropy);
      $("btnReset").addEventListener("click", resetAll);
      $("btnVerify").addEventListener("click", verifyWif);
    }
  });
  require_app();
})();
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
//# sourceMappingURL=bundle.js.map
