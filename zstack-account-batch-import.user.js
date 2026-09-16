// ==UserScript==
// @name         ZStack 批量账户导入
// @namespace    https://docs.scriptcat.org/
// @version      0.2.0
// @description  在 ZStack Cloud 已登录页面批量创建子账户：读取 CSV/TXT/XLSX，调用 GraphQL 网关自动导入，含预览、进度、错误汇总。支持"班级"列自动创建/绑定计费价目。在任意已登录页面(默认 /settings/account-information)均可唤起。
// @author       You
// @match        http://10.13.0.45/*
// @match        http://10.13.0.45:5000/*
// @match        https://10.13.0.45:5000/*
// @match        http://10.13.0.45:5000/settings/account-information/*
// @include      http://10.13.0.45/*
// @include      http://10.13.0.45:5000/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=10.13.0.45
// @grant        none
// @noframes
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    /* ======================================================================
     * 0. 常量与全局状态
     * ====================================================================== */
    var HOST = location.hostname;                 // 10.13.0.45
    var GQL_BASE = location.origin + '/graphql';  // http://10.13.0.45:5000/graphql
    var PREFIX = 'zsbi-';                          // 样式/元素前缀，避免与 ZStack 冲突

    var STATE = {
        sessionId: null,        // 捕获到的 x-session-id
        busy: false,            // 是否在导入
        stopRequested: false,
        rows: [],               // 解析后的原始行(对象数组)
        results: [],            // 每行导入结果
        manualSessionSaved: false
    };

    // 模板字段：学号 / 姓名 / 密码 / 班级；密码留空时使用该默认值
    // 班级列的值直接作为「计费价目」的名称；留空则使用默认计费价目
    var DEFAULT_PASSWORD = '123456';

    /* ======================================================================
     * 1. 纯 JS SHA-512（BigInt 实现）
     *    —— http 内网(非安全上下文)下 crypto.subtle 不可用，必须手写。
     *    运行时自检：sha512('123456') 必须等于 HAR 抓包值，否则禁用导入。
     * ====================================================================== */
    var MASK64 = 0xffffffffffffffffn;

    function sha512(str) {
        var text = new TextEncoder().encode(String(str));

        // 1) 填充
        var withOne = new Uint8Array(text.length + 1);
        withOne.set(text);
        withOne[text.length] = 0x80;
        while (withOne.length % 128 !== 112) {
            var tmp = new Uint8Array(withOne.length + 1);
            tmp.set(withOne);
            withOne = tmp;
        }
        var padded = new Uint8Array(withOne.length + 16);
        padded.set(withOne);
        // 长度(位) 大端写入最后 8 字节；假定消息 < 2^64 位
        var lenBits = BigInt(text.length) * 8n;
        for (var i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = Number((lenBits >> BigInt(i * 8)) & 0xffn);
        }

        // 2) 常量 K[80]
        var K = [
            0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
            0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
            0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
            0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
            0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
            0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
            0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
            0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
            0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
            0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
            0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
            0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
            0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
            0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
            0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
            0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
            0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
            0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
            0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
            0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
        ];

        function rotr(x, n) { return (x >> n) | (x << (64n - n)); }

        var H = [
            0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
            0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
        ];

        for (var off = 0; off < padded.length; off += 128) {
            var w = new Array(80);
            for (var t = 0; t < 16; t++) {
                w[t] = 0n;
                for (var j = 0; j < 8; j++) {
                    w[t] = (w[t] << 8n) | BigInt(padded[off + t * 8 + j]);
                }
            }
            for (var t2 = 16; t2 < 80; t2++) {
                var s0 = rotr(w[t2 - 15], 1n) ^ rotr(w[t2 - 15], 8n) ^ (w[t2 - 15] >> 7n);
                var s1 = rotr(w[t2 - 2], 19n) ^ rotr(w[t2 - 2], 61n) ^ (w[t2 - 2] >> 6n);
                w[t2] = (w[t2 - 16] + s0 + w[t2 - 7] + s1) & MASK64;
            }
            var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
            for (var round = 0; round < 80; round++) {
                var S1 = rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n);
                var ch = (e & f) ^ ((~e) & g);
                var temp1 = (h + S1 + ch + K[round] + w[round]) & MASK64;
                var S0 = rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var temp2 = (S0 + maj) & MASK64;
                h = g; g = f; f = e; e = (d + temp1) & MASK64;
                d = c; c = b; b = a; a = (temp1 + temp2) & MASK64;
            }
            H[0] = (H[0] + a) & MASK64; H[1] = (H[1] + b) & MASK64; H[2] = (H[2] + c) & MASK64;
            H[3] = (H[3] + d) & MASK64; H[4] = (H[4] + e) & MASK64; H[5] = (H[5] + f) & MASK64;
            H[6] = (H[6] + g) & MASK64; H[7] = (H[7] + h) & MASK64;
        }
        return H.map(function (x) { return x.toString(16).padStart(16, '0'); }).join('');
    }

    // === SHA-512 自检：与 HAR 中 createAccount 抓包值一致才算可用 ===
    var HASH_OK = sha512('123456') === 'ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413';

    /* ======================================================================
     * 2. 工具函数
     * ====================================================================== */
    function randHex(len) {
        var out = '';
        if (window.crypto && crypto.getRandomValues) {
            var bytes = new Uint8Array(Math.ceil(len / 2));
            crypto.getRandomValues(bytes);
            for (var i = 0; i < bytes.length; i++) { out += bytes[i].toString(16).padStart(2, '0'); }
            return out.slice(0, len);
        }
        // 兜底
        for (var j = 0; j < len; j++) { out += '0123456789abcdef'[Math.floor(Math.random() * 16)]; }
        return out;
    }

    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                if (k === 'class') node.className = attrs[k];
                else if (k === 'style') { node.style.cssText = attrs[k]; }
                else if (k.slice(0, 2) === 'on') node.addEventListener(k.slice(2), attrs[k]);
                else node.setAttribute(k, attrs[k]);
            });
        }
        // 容错：允许传单个字符串/节点，而不要求必须是数组
        if (children != null) {
            if (!Array.isArray(children)) children = [children];
            children.forEach(function (c) {
                if (c == null) return;
                node.appendChild((typeof c === 'string' || typeof c === 'number')
                    ? document.createTextNode(String(c)) : c);
            });
        }
        return node;
    }

    function download(name, content, mime) {
        var blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    }

    function csvEscape(v) {
        v = v == null ? '' : String(v);
        return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }

    function log(msg, kind) {
        var box = document.getElementById(PREFIX + 'log');
        if (!box) return;
        if (box.children.length > 300) box.textContent = '';
        var div = el('div', { class: PREFIX + 'logline ' + (kind || 'info') }, [String(msg)]);
        box.appendChild(div);
        box.scrollTop = box.scrollHeight;
    }

    function setStatus(kind, msg) {
        var s = document.getElementById(PREFIX + 'session-status');
        if (!s) return;
        s.textContent = msg;
        s.className = PREFIX + 'status-badge ' + (kind || 'warn');
    }

    /* ======================================================================
     * 3. 会话捕获
     *    —— 页面自身发往 /graphql 的请求都带 x-session-id，
     *       拦截 fetch / XHR 用它的值即可复用浏览器已登录会话。
     * ====================================================================== */
    function startSessionCapture() {
        // 3.1 fetch
        var origFetch = window.fetch;
        if (typeof origFetch === 'function') {
            window.fetch = function () {
                var url = arguments[0];
                var opts = arguments[1] || {};
                try {
                    if (typeof url === 'string' && url.indexOf('/graphql') !== -1) {
                        var hdrs = opts.headers;
                        var sid = null;
                        if (hdrs) {
                            if (typeof Headers !== 'undefined' && hdrs instanceof Headers) sid = hdrs.get('x-session-id');
                            else if (Array.isArray(hdrs)) {
                                for (var i = 0; i < hdrs.length; i++) {
                                    if (String(hdrs[i][0]).toLowerCase() === 'x-session-id') { sid = hdrs[i][1]; break; }
                                }
                            } else if (typeof hdrs === 'object' && !(hdrs instanceof Headers)) {
                                var k = Object.keys(hdrs).filter(function (x) { return x.toLowerCase() === 'x-session-id'; })[0];
                                if (k) sid = hdrs[k];
                            }
                        }
                        if (sid) adoptSession(String(sid).trim());
                    }
                } catch (err) { /* 忽略解析错误 */ }
                return origFetch.apply(this, arguments);
            };
        }

        // 3.2 XHR
        var origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
        XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
            try {
                if (String(name).toLowerCase() === 'x-session-id' && String(value).length === 32) adoptSession(String(value).trim());
            } catch (err) { /* 忽略 */ }
            return origSetHeader.apply(this, arguments);
        };

        // 3.3 存储扫描兜底（页面可能把 session 存在 localStorage/sessionStorage）
        scanStorageForSession();
    }

    // 在 localStorage / sessionStorage 中寻找 32 位 hex 的会话候选
    function scanStorageForSession() {
        if (STATE.sessionId) return;
        var found = [];
        ['localStorage', 'sessionStorage'].forEach(function (storeName) {
            try {
                var store = window[storeName];
                for (var i = 0; i < store.length; i++) {
                    var k = store.key(i);
                    var v = store.getItem(k);
                    if (/^[0-9a-f]{32}$/.test(v || '')) found.push({ key: k, value: v });
                }
            } catch (err) { /* 忽略跨域存储异常 */ }
        });
        STATE.storageCandidates = found;
        // 仅当只有一个候选时才自动采用，避免误用无关的 32 位 hex
        if (found.length === 1) adoptSession(found[0].value);
    }

    function adoptSession(sid) {
        if (STATE.sessionId && STATE.sessionId === sid) return;
        STATE.sessionId = sid;
        var k = STATE.sessionId ? 'ok' : 'warn';
        setStatus(k, '已捕获会话：' + sid.slice(0, 8) + '…' + sid.slice(-4));
        var pv = document.getElementById(PREFIX + 'session-value');
        if (pv) pv.value = sid;
        var t = document.getElementById(PREFIX + 'session-tip');
        if (t) t.textContent = '会话已就绪，可开始导入';
    }

    /* ======================================================================
     * 4. GraphQL 客户端
     * ====================================================================== */
    function gql(opName, query, variables, needSession) {
        if (needSession && !STATE.sessionId) return Promise.reject(new Error('尚未捕获到会话(x-session-id)'));
        return fetch(GQL_BASE + '?gql=' + opName, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'content-type': 'application/json',
                'x-session-id': STATE.sessionId || '',
                'apollographql-client-name': 'zstack-ui-client',
                'apollographql-client-version': '3.11.8',
                'accept': '*/*'
            },
            body: JSON.stringify({ operationName: opName, query: query, variables: variables || {} })
        }).then(function (r) { return r.json(); }).then(function (j) {
            if (j && j.errors && j.errors.length) {
                var firstErr = j.errors[0];
                var msg = (firstErr.message || JSON.stringify(firstErr)) + (firstErr.extensions && firstErr.extensions.message ? ' | ' + firstErr.extensions.message : '');
                throw new Error(msg.slice(0, 500));
            }
            return (j && j.data) || {};
        });
    }

    /* ======================================================================
     * 5. 文件解析
     *    TXT：一行一个用户名，密码统一（面板输入）
     *    CSV：表头 用户名/密码/类型/描述（含别名），GBK 自动识别
     *    XLSX：按需动态加载 SheetJS，失败提示转 CSV
     * ====================================================================== */
    function decodeBytes(buf, hasUtf8Bom) {
        if (hasUtf8Bom) return new TextDecoder('utf-8').decode(buf);
        var txt = new TextDecoder('utf-8').decode(buf);
        if (txt.indexOf('\uFFFD') === -1) return txt;          // 无替换字符 => 是 UTF-8
        try {
            return new TextDecoder('gbk').decode(buf);          // 否则按 GBK
        } catch (err) {
            return txt;
        }
    }

    function parseCSV(text) {
        var rows = [];
        var fields = [];
        var cur = '';
        var rowArr = [];
        var inQ = false;
        text = text.replace(/^\uFEFF/, '');
        for (var i = 0; i < text.length; i++) {
            var c = text[i];
            if (inQ) {
                if (c === '"') {
                    if (text[i + 1] === '"') { cur += '"'; i++; }
                    else inQ = false;
                } else cur += c;
            } else if (c === '"' && cur === '') {
                inQ = true;
            } else if (c === ',') {
                rowArr.push(cur); cur = '';
            } else if (c === '\n' || c === '\r') {
                if (c === '\r' && text[i + 1] === '\n') i++;
                rowArr.push(cur); cur = '';
                if (rowArr.length && rowArr.some(function (x) { return x !== ''; })) {
                    if (!fields.length) fields = rowArr.slice();
                    else rows.push(rowArr.slice());
                }
                rowArr = [];
            } else cur += c;
        }
        if (cur !== '' || rowArr.length) {
            rowArr.push(cur);
            if (rowArr.some(function (x) { return x !== ''; })) {
                if (!fields.length) fields = rowArr.slice();
                else rows.push(rowArr.slice());
            }
        }
        return { fields: fields, rows: rows };
    }

    // 模板列名按业务语义显示，顺序约定：
    //   学号 -> 账户名称(name) / 姓名 -> 简介(description) / 密码 -> 账户密码(password) / 班级 -> 计费价目名称(className)
    // 其它列一律忽略并提示，避免字段静默丢失。
    function normalizeHeaders(fields) {
        var map = { ignored: [] };
        function setIfAbsent(key, idx) { if (map[key] == null) map[key] = idx; }

        (fields || []).forEach(function (f, idx) {
            var raw = String(f).trim().replace(/^\uFEFF/, '');
            var key = raw.toLowerCase();
            var norm = key.replace(/[\s（()）]+/g, '');
            var k3 = key.replace(/[^a-z0-9]/g, '');

            if (norm === '学号' || norm === '工号' || norm === '编号' || norm === '账号' || norm === '账户'
                || norm === '名称' || norm === '用户名'
                || k3 === 'name' || k3 === 'username' || k3 === 'account' || k3 === 'id' || k3 === 'no') {
                setIfAbsent('name', idx);                     // 学号 -> name
            } else if (norm === '姓名' || norm === '名字' || norm === '简介' || norm === '描述' || norm === '备注'
                || k3 === 'description' || k3 === 'desc' || k3 === 'intro' || k3 === 'remark') {
                setIfAbsent('description', idx);              // 姓名 -> description
            } else if (norm === '密码' || k3 === 'password' || k3 === 'pwd') {
                setIfAbsent('password', idx);
            } else if (norm === '班级' || norm === '计费价目' || norm === '价目'
                || k3 === 'class' || k3 === 'classname' || k3 === 'classtype' || k3 === 'price' || k3 === 'pricetable') {
                setIfAbsent('className', idx);                 // 班级 -> 计费价目名称
            } else if (raw) {
                map.ignored.push(raw);                        // 记录并忽略，不静默丢字段
            }
        });
        return map;
    }

    var XLSX_CDNS = [
        'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js',
        'https://unpkg.com/xlsx@0.18.5/dist/xlsx.full.min.js',
        'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'
    ];
    var xlsxCdnIdx = 0;

    function loadXlsxFallback(file, onDone, onFail) {
        function tryNext() {
            if (xlsxCdnIdx >= XLSX_CDNS.length) {
                onFail('无法加载 XLSX 解析库（外网 CDN 均不可达）。请点击「下载数据导入模板」得到 CSV 后填写上传，或转存 CSV 后重试。');
                return;
            }
            var src = XLSX_CDNS[xlsxCdnIdx++];
            log('尝试加载解析库：' + src);
            var s = document.createElement('script');
            s.src = src;
            s.onload = function () {
                if (typeof XLSX !== 'undefined') parseXlsx(file, onDone, onFail);
                else tryNext();
            };
            s.onerror = tryNext;
            document.head.appendChild(s);
        }
        tryNext();
    }

    function parseFile(file, onDone, onFail) {
        var reader = new FileReader();
        reader.onerror = function () { onFail('读取文件失败'); };
        if (/\.xlsx?$/i.test(file.name)) {
            // XLS/XLSX(BIFF/OOXML) 需要 SheetJS：优先用页面已有的，否则多 CDN 动态加载
            if (typeof XLSX !== 'undefined') { parseXlsx(file, onDone, onFail); }
            else { loadXlsxFallback(file, onDone, onFail); }
            return;
        }
        reader.onload = function () {
            try {
                var buf = new Uint8Array(reader.result);
                var hasBom = buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF;
                var text = decodeBytes(buf, hasBom);
                if (/\.txt$/i.test(file.name)) { onDone({ kind: 'txt', text: text }); return; }
                onDone({ kind: 'csv', parsed: parseCSV(text), text: text });
            } catch (err) { onFail('解析失败：' + err.message); }
        };
        reader.readAsArrayBuffer(file);
    }

    function parseXlsx(file, onDone, onFail) {
        var reader = new FileReader();
        reader.onload = function () {
            try {
                var wb = XLSX.read(new Uint8Array(reader.result), { type: 'array' });
                var ws = wb.Sheets[wb.SheetNames[0]];
                var arr = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
                var fields = (arr[0] || []).map(function (x) { return String(x); });
                var rows = arr.slice(1).map(function (r) {
                    return Array.prototype.slice.call(r);
                });
                onDone({ kind: 'csv', parsed: { fields: fields, rows: rows } });
            } catch (err) { onFail('XLSX 解析失败：' + err.message); }
        };
        reader.onerror = function () { onFail('读取文件失败'); };
        reader.readAsArrayBuffer(file);
    }

    /* ======================================================================
     * 6. 行构建与校验
     * ====================================================================== */
    function buildRows(parsed, fallbackPassword) {
        var firstRow = parsed.fields || [];
        var map = normalizeHeaders(firstRow);
        var headerConfirmed = Object.keys(map).some(function (k) { return k !== 'ignored'; });

        // 关键：无表头时首行是数据，绝不能被当成表头丢掉
        var rawList = headerConfirmed
            ? (parsed.rows || [])
            : [firstRow].concat(parsed.rows || []);
        var firstDataLine = headerConfirmed ? 2 : 1;         // 用于报错定位的行号

        function cell(rRaw, idx) {
            if (idx == null) return '';
            var v = rRaw[idx];
            return v == null ? '' : String(v).trim();
        }

        var rows = [];
        rawList.forEach(function (rRaw, idx) {
            var r = {};
            if (headerConfirmed) {
                r.name = cell(rRaw, map.name);                                  // 学号
                r.description = cell(rRaw, map.description);                    // 姓名
                r.password = cell(rRaw, map.password);                          // 密码
                r.className = cell(rRaw, map.className);                        // 班级 -> 计费价目
            } else {
                // 无表头：按 学号,姓名,密码,班级 的位置约定解析
                r.name = cell(rRaw, 0);
                r.description = cell(rRaw, 1);
                r.password = cell(rRaw, 2);
                r.className = cell(rRaw, 3);
            }
            // 密码留空 -> 面板"默认密码" -> 内置默认 123456
            if (!r.password) r.password = fallbackPassword || DEFAULT_PASSWORD;
            r.line = idx + firstDataLine;
            r._idx = idx;
            rows.push(r);
        });
        return { rows: rows, ignored: map.ignored || [] };
    }

    // 校验规则：学号 必填、≤255；姓名 选填、≤256；班级 选填、≤128；密码 有默认值(123456)故不会为空
    function validateRow(r) {
        var errs = [];
        if (!r.name) errs.push('缺学号');
        else if (r.name.length > 255) errs.push('学号超长(>255)');
        else if (r.name !== r.name.trim()) errs.push('学号首尾不能有空格');
        else if (!/^[\u4e00-\u9fa5A-Za-z0-9_.@\- ]+$/.test(r.name)) errs.push('学号含不支持的字符');
        else if (r.name.toLowerCase() === 'admin') errs.push('不允许创建 admin');
        if (r.description && r.description.length > 256) errs.push('姓名超长(>256)');
        if (r.className && r.className.length > 128) errs.push('班级超长(>128)');
        if (r.password == null || r.password === '') errs.push('缺密码');
        else if (!/^[\x20-\x7E]+$/.test(r.password)) errs.push('密码须为 ASCII 可见字符');
        else if (r.password.length > 255) errs.push('密码超长(>255)');
        return errs;
    }

    function detectDuplicates(rows) {
        var seen = {};
        rows.forEach(function (r) {
            var n = r.name;
            if (!seen[n]) seen[n] = [];
            seen[n].push(r);
        });
        Object.keys(seen).forEach(function (n) {
            if (seen[n].length > 1) seen[n][0]._dup = true;
        });
        rows.forEach(function (r) {
            r._dup = r._dup || seen[r.name].length > 1;
        });
    }

    /* ======================================================================
     * 7. 执行引擎：逐行 createAccount + operationLogList 轮询
     *    附带：计费价目（BillingsPriceTable）查询/创建 + 账户绑定
     * ====================================================================== */
    var CREATE_MUTATION =
        'mutation createAccount($input: CreateAccountInput!) { createAccount(input: $input) { actionId __typename } }';
    var LOG_QUERY =
        'query operationLogList($conditions: [Condition!], $start: Int, $limit: Int, $sortBy: String, $sortDirection: SortDirectionValidValues) { ' +
        'operationLogList(conditions: $conditions, start: $start, limit: $limit, sortBy: $sortBy, sortDirection: $sortDirection) { ' +
        'total list { actionId name status progress createDate lastOpDate __typename } __typename } }';

    // —— 计费价目相关（字段与 UI 抓包一致）——
    var PRICE_TABLE_LIST_QUERY =
        'query billingsPriceTableList($conditions: [Condition!], $start: Int, $limit: Int) { ' +
        'billingsPriceTableList(conditions: $conditions, start: $start, limit: $limit, replyWithCount: true) { ' +
        'total list { uuid name isDefault __typename } __typename } }';
    var CREATE_PRICE_TABLE_MUTATION =
        'mutation createBillingsPriceTable($input: CreateBillingsPriceTableActionInput!) { ' +
        'createBillingsPriceTable(input: $input) { actionId __typename } }';
    var ACCOUNT_LIST_QUERY =
        'query accountList($conditions: [Condition!], $start: Int, $limit: Int) { ' +
        'accountList(conditions: $conditions, start: $start, limit: $limit, replyWithCount: true) { ' +
        'total list { uuid name __typename } __typename } }';
    var BIND_PRICE_TABLE_MUTATION =
        'mutation changeAccountBillingsPriceTable($input: ChangeAccountBillingsPriceTableInput!) { ' +
        'changeAccountBillingsPriceTable(input: $input) { actionId __typename } }';


    function pollAction(actionId) {
        var tries = 0;
        var MAX = 80;  // 80 * 1.5s = 120s
        return new Promise(function (resolve, reject) {
            (function tick() {
                if (STATE.stopRequested) return reject(new Error('已手动停止'));
                gql('operationLogList', LOG_QUERY, {
                    conditions: [{ key: 'actionId', op: 'in', values: [actionId] }],
                    start: 0, limit: 10
                }, true).then(function (data) {
                    var logs = (data.operationLogList && data.operationLogList.list) || [];
                    var hit = logs.filter(function (l) { return l.actionId === actionId; })[0];
                    if (hit) {
                        if (hit.status === 'Success') return resolve({ status: 'Success', progress: hit.progress });
                        if (hit.status === 'Failed') return reject(new Error('Action 执行失败'));
                    }
                    if (++tries >= MAX) return reject(new Error('等待执行结果超时(120s)'));
                    setTimeout(tick, 1500);
                }).catch(function (e) {
                    if (/超时|停止/.test(e.message)) return reject(e);
                    if (++tries >= MAX) return reject(new Error('轮询失败：' + e.message));
                    setTimeout(tick, 1500);
                });
            })();
        });
    }

    function createOne(row) {
        var actionId = randHex(32);
        var payload = {
            type: 'Normal',
            name: row.name,
            password: sha512(row.password)
        };
        if (row.description) payload.description = row.description;
        var variables = {
            input: {
                payload: payload,
                action: { name: '创建子账户', total: 1, actionId: actionId }
            }
        };
        return gql('createAccount', CREATE_MUTATION, variables, true).then(function (data) {
            var returnedActionId = (data.createAccount && data.createAccount.actionId) || actionId;
            return pollAction(returnedActionId);
        }).then(function (res) { return { actionId: actionId, detail: res }; });
    }

    /* ---- 计费价目：查询(带缓存) / 确保存在 / 查账户 uuid / 绑定 ---- */
    var PRICE_CACHE = { map: null };     // name -> uuid（每轮导入开始时重置）

    function loadPriceTableMap() {
        // 分页拉全量，建立 name -> uuid 映射
        var all = [];
        var start = 0, LIMIT = 200;
        return (function page() {
            return gql('billingsPriceTableList', PRICE_TABLE_LIST_QUERY,
                { conditions: [], start: start, limit: LIMIT }, true).then(function (data) {
                    var resp = data.billingsPriceTableList || {};
                    all = all.concat(resp.list || []);
                    if (all.length < (resp.total || 0)) { start += LIMIT; return page(); }
                    var map = {};
                    all.forEach(function (t) { map[t.name] = t.uuid; });
                    PRICE_CACHE.map = map;
                    return map;
                });
        })();
    }

    // 返回 Promise<uuid>；班级为空 -> null（使用默认计费价目，不绑定）
    function ensurePriceTable(name) {
        if (!name) return Promise.resolve(null);
        if (!PRICE_CACHE.map) return loadPriceTableMap().then(function () { return ensurePriceTable(name); });
        if (PRICE_CACHE.map[name]) return Promise.resolve(PRICE_CACHE.map[name]);

        var actionId = randHex(32);
        var variables = {
            input: {
                payload: { name: name },
                action: { name: '创建计费价目', total: 1, actionId: actionId }
            }
        };
        return gql('createBillingsPriceTable', CREATE_PRICE_TABLE_MUTATION, variables, true)
            .then(function (data) { return pollAction((data.createBillingsPriceTable && data.createBillingsPriceTable.actionId) || actionId); })
            .then(function () { return loadPriceTableMap(); })   // 刷新缓存拿到新 uuid
            .then(function (map) {
                if (!map[name]) throw new Error('计费价目「' + name + '」创建后未能查询到');
                log('已创建计费价目：' + name, 'ok');
                return map[name];
            });
    }

    function getAccountUuidByName(name) {
        return gql('accountList', ACCOUNT_LIST_QUERY, {
            conditions: [{ key: 'name', op: 'in', values: [name] }],
            start: 0, limit: 10
        }, true).then(function (data) {
            var list = (data.accountList && data.accountList.list) || [];
            var hit = list.filter(function (a) { return a.name === name; })[0];
            if (!hit) throw new Error('账户创建成功但未查询到 uuid，无法绑定计费价目');
            return hit.uuid;
        });
    }

    function bindAccountPriceTable(accountUuid, tableUuid) {
        var actionId = randHex(32);
        var variables = {
            input: {
                payload: [{ accountUuid: accountUuid, tableUuid: tableUuid }],
                action: { name: '更换计费价目', total: 1, actionId: actionId }
            }
        };
        return gql('changeAccountBillingsPriceTable', BIND_PRICE_TABLE_MUTATION, variables, true)
            .then(function (data) { return pollAction((data.changeAccountBillingsPriceTable && data.changeAccountBillingsPriceTable.actionId) || actionId); });
    }


    function runImport() {
        if (!HASH_OK) { log('SHA-512 自检失败，已禁用导入（请勿继续）', 'err'); return; }
        if (!STATE.sessionId) { log('尚未捕获会话，无法导入', 'err'); setStatus('err', '未捕获会话'); return; }
        if (!STATE.rows.length) { log('没有可导入的数据', 'err'); return; }
        if (STATE.busy) return;

        STATE.results = buildResults();
        var valid = STATE.results.filter(function (x) { return x.status === 'pending'; });
        if (!valid.length) { log('没有有效的行', 'err'); return; }

        // 简单确认（含计费价目信息）
        var invalidCount = STATE.results.length - valid.length;
        var classNames = [];
        valid.forEach(function (res) {
            var c = res.row.className;
            if (c && classNames.indexOf(c) === -1) classNames.push(c);
        });
        var confirmMsg = '将创建 ' + valid.length + ' 个账户' + (invalidCount ? '（另 ' + invalidCount + ' 行无效将被跳过）' : '');
        if (classNames.length) confirmMsg += '，并涉及 ' + classNames.length + ' 个班级计费价目（不存在的将自动创建）';
        if (!confirm(confirmMsg + '，确定开始吗？')) return;

        STATE.busy = true;
        STATE.stopRequested = false;
        setUiBusy(true);
        PRICE_CACHE.map = null;   // 每轮导入重新拉取计费价目缓存

        var total = valid.length;
        var done = 0, ok = 0, fail = 0;
        STATE.progress = { done: 0, ok: 0, fail: 0, total: total };
        updateProgress();
        renderResults();
        log('开始导入，共 ' + total + ' 个账户…', 'info');

        // 阶段一：确保所有班级计费价目存在（先建价目，再建账户）
        var chain = Promise.resolve();
        if (classNames.length) {
            log('检查/创建计费价目：' + classNames.join('、'), 'info');
            chain = chain.then(function () { return loadPriceTableMap(); });
            classNames.forEach(function (c) {
                chain = chain.then(function () {
                    if (STATE.stopRequested) return;
                    return ensurePriceTable(c).catch(function (e) {
                        log('计费价目「' + c + '」准备失败：' + e.message + '（该班级的账户将不绑定价目）', 'warn');
                    });
                });
            });
        }

        // 阶段二：逐个创建账户；创建成功后按班级绑定计费价目
        valid.forEach(function (res) {
            chain = chain.then(function () {
                if (STATE.stopRequested) return;
                res.status = 'running';
                renderResults();
                return createOne(res.row)
                    .then(function (r) {
                        res.status = 'success'; res.message = 'Success'; res.actionId = r.actionId;
                        ok++;
                        // 班级为空 -> 使用默认计费价目，无需绑定
                        if (!res.row.className) { res.bindMsg = '默认价目'; return; }
                        var tableUuid = PRICE_CACHE.map && PRICE_CACHE.map[res.row.className];
                        if (!tableUuid) {
                            res.bindMsg = '价目未就绪，未绑定';
                            log('[' + res.row.name + '] 计费价目「' + res.row.className + '」不可用，已跳过绑定', 'warn');
                            return;
                        }
                        return getAccountUuidByName(res.row.name)
                            .then(function (accountUuid) { return bindAccountPriceTable(accountUuid, tableUuid); })
                            .then(function () { res.bindMsg = '已绑定价目「' + res.row.className + '」'; })
                            .catch(function (e) {
                                res.bindMsg = '账户已建，绑定价目失败：' + e.message;
                                log('[' + res.row.name + '] ' + res.bindMsg, 'warn');
                            });
                    })
                    .catch(function (e) {
                        res.status = 'failed'; res.message = String(e.message || e);
                        fail++;
                        log('[' + res.row.name + '] 失败：' + res.message, 'err');
                    })
                    .then(function () {
                        done++;
                        STATE.progress = { done: done, ok: ok, fail: fail, total: total };
                        updateProgress();
                        renderResults();
                    });
            });
        });

        chain.then(function () {
            STATE.busy = false;
            setUiBusy(false);
            log('导入结束：成功 ' + ok + '，失败 ' + fail + (STATE.stopRequested ? '（已手动停止）' : ''),
                fail === 0 && done === total ? 'ok' : 'warn');
        });
    }

    /* ======================================================================
     * 8. UI
     * ====================================================================== */
    // 视觉对齐 ZStack Cloud：主色由页面取样(--zsbi-primary)，4px 圆角、1px 浅灰描边、
    // 白底 + #fafafa 填充、#262626/#8c8c8c 文字层级。
    var STYLES = '\n' +
        '#' + PREFIX + 'fab{position:fixed;right:24px;bottom:32px;z-index:2147483000;height:40px;padding:0 20px;' +
        'border-radius:4px;background:var(--zsbi-primary,#7c3aed);color:#fff;border:none;cursor:pointer;font-size:14px;' +
        'box-shadow:0 2px 8px rgba(0,0,0,.15);display:flex;align-items:center;justify-content:center;transition:background .2s;}\n' +
        '#' + PREFIX + 'fab:hover{background:var(--zsbi-primary-hover,#6429c9);}\n' +
        '#' + PREFIX + 'panel{position:fixed;top:7vh;right:4vw;width:880px;max-width:94vw;height:86vh;z-index:2147483001;' +
        'background:#fff;border:1px solid #f0f0f0;border-radius:6px;box-shadow:0 6px 24px rgba(0,0,0,.12);' +
        'display:none;flex-direction:column;font-size:14px;line-height:1.5715;color:#262626;' +
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue","PingFang SC","Microsoft YaHei",Arial,sans-serif;}\n' +
        '#' + PREFIX + 'panel *{box-sizing:border-box;}\n' +
        '#' + PREFIX + 'panel.' + PREFIX + 'open{display:flex;}\n' +
        '#' + PREFIX + 'header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;' +
        'border-bottom:1px solid #f0f0f0;background:#fff;border-radius:6px 6px 0 0;flex:none;}\n' +
        '#' + PREFIX + 'header .title{font-size:16px;font-weight:600;color:#262626;}\n' +
        '#' + PREFIX + 'close{cursor:pointer;font-size:16px;line-height:1;color:#8c8c8c;background:none;border:none;padding:4px;}\n' +
        '#' + PREFIX + 'close:hover{color:#262626;}\n' +
        '#' + PREFIX + 'body{padding:20px;overflow:auto;flex:1;}\n' +
        '#' + PREFIX + 'sessionbar{display:flex;align-items:center;gap:8px;padding:12px 16px;border-radius:4px;' +
        'background:#fafafa;border:1px solid #f0f0f0;margin-bottom:16px;flex-wrap:wrap;}\n' +
        '#' + PREFIX + 'status-badge{padding:1px 8px;border-radius:4px;font-size:12px;line-height:20px;' +
        'border:1px solid transparent;white-space:nowrap;}\n' +
        '#' + PREFIX + 'status-badge.ok{background:#f6ffed;border-color:#b7eb8f;color:#52c41a;}\n' +
        '#' + PREFIX + 'status-badge.warn{background:#fffbe6;border-color:#ffe58f;color:#faad14;}\n' +
        '#' + PREFIX + 'status-badge.err{background:#fff2f0;border-color:#ffccc7;color:#ff4d4f;}\n' +
        '#' + PREFIX + 'session-value{flex:1;min-width:220px;height:32px;border:1px solid #d9d9d9;border-radius:4px;' +
        'padding:4px 11px;font-size:12px;font-family:Consolas,Monaco,monospace;color:#262626;outline:none;transition:border-color .2s;}\n' +
        '#' + PREFIX + 'session-value:hover{border-color:var(--zsbi-primary-border,#b37fef);}\n' +
        '#' + PREFIX + 'session-value:focus{border-color:var(--zsbi-primary,#7c3aed);box-shadow:0 0 0 2px var(--zsbi-primary-light,#f4edfd);}\n' +
        '#' + PREFIX + 'session-tip{width:100%;color:#8c8c8c;font-size:12px;}\n' +
        '#' + PREFIX + 'btn{height:32px;padding:0 15px;border-radius:4px;background:var(--zsbi-primary,#7c3aed);color:#fff;' +
        'border:1px solid var(--zsbi-primary,#7c3aed);cursor:pointer;font-size:14px;line-height:1;' +
        'font-family:inherit;transition:all .2s;white-space:nowrap;}\n' +
        '#' + PREFIX + 'btn:hover{background:var(--zsbi-primary-hover,#6429c9);border-color:var(--zsbi-primary-hover,#6429c9);}\n' +
        '#' + PREFIX + 'btn.secondary{background:#fff;color:#262626;border-color:#d9d9d9;}\n' +
        '#' + PREFIX + 'btn.secondary:hover{background:#fff;color:var(--zsbi-primary,#7c3aed);border-color:var(--zsbi-primary,#7c3aed);}\n' +
        '#' + PREFIX + 'btn.danger{background:#fff;color:#ff4d4f;border-color:#ff4d4f;}\n' +
        '#' + PREFIX + 'btn.danger:hover{background:#ff4d4f;color:#fff;border-color:#ff4d4f;}\n' +
        '#' + PREFIX + 'btn:disabled,.' + PREFIX + 'disabled{opacity:.4;cursor:not-allowed;}\n' +
        '#' + PREFIX + 'drop{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 20px;' +
        'border:1px dashed #d9d9d9;border-radius:4px;background:#fafafa;cursor:pointer;margin-bottom:16px;transition:all .2s;}\n' +
        '#' + PREFIX + 'drop:hover{border-color:var(--zsbi-primary,#7c3aed);background:var(--zsbi-primary-light,#f9f5fe);}\n' +
        '#' + PREFIX + 'drop b{font-size:14px;font-weight:500;color:#262626;}\n' +
        '#' + PREFIX + 'drop small{color:#8c8c8c;margin-top:8px;font-size:12px;}\n' +
        '#' + PREFIX + 'controls{display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap;}\n' +
        '#' + PREFIX + 'controls label{color:#262626;font-size:14px;}\n' +
        '#' + PREFIX + 'defpass{width:170px;height:32px;border:1px solid #d9d9d9;border-radius:4px;padding:4px 11px;' +
        'font-size:14px;color:#262626;outline:none;transition:border-color .2s;}\n' +
        '#' + PREFIX + 'defpass:hover{border-color:var(--zsbi-primary-border,#b37fef);}\n' +
        '#' + PREFIX + 'defpass:focus{border-color:var(--zsbi-primary,#7c3aed);box-shadow:0 0 0 2px var(--zsbi-primary-light,#f4edfd);}\n' +
        '#' + PREFIX + 'template-samples{font-size:12px;color:#8c8c8c;line-height:1.9;margin-bottom:16px;}\n' +
        '#' + PREFIX + 'template-samples code{background:#fafafa;border:1px solid #f0f0f0;padding:1px 6px;border-radius:4px;' +
        'color:#595959;font-family:Consolas,Monaco,monospace;font-size:12px;}\n' +
        '#' + PREFIX + 'preview-label{font-size:14px;font-weight:500;color:#262626;margin:0 0 8px;}\n' +
        '#' + PREFIX + 'tablewrap{overflow:auto;max-height:320px;border:1px solid #f0f0f0;border-radius:4px;}\n' +
        '#' + PREFIX + 'table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;}\n' +
        '#' + PREFIX + 'table th{background:#fafafa;position:sticky;top:0;z-index:1;padding:12px;text-align:left;' +
        'color:#262626;font-weight:500;border-bottom:1px solid #f0f0f0;white-space:nowrap;}\n' +
        '#' + PREFIX + 'table td{padding:12px;border-bottom:1px solid #f0f0f0;color:#262626;word-break:break-all;vertical-align:top;}\n' +
        '#' + PREFIX + 'table tr:last-child td{border-bottom:none;}\n' +
        '#' + PREFIX + 'table tr.invalid td{background:#fff2f0;}\n' +
        '#' + PREFIX + 'table tr.failed td{background:#fff2f0;}\n' +
        '#' + PREFIX + 'table tr.success td{background:#f6ffed;}\n' +
        '#' + PREFIX + 'table tr.running td{background:#fffbe6;}\n' +
        '#' + PREFIX + 'summary{padding:8px 12px;color:#8c8c8c;font-size:13px;border-top:1px solid #f0f0f0;background:#fafafa;}\n' +
        '#' + PREFIX + 'bar{height:6px;background:#f0f0f0;border-radius:3px;overflow:hidden;margin:16px 0 6px;}\n' +
        '#' + PREFIX + 'bar > div{height:100%;width:0;background:var(--zsbi-primary,#7c3aed);border-radius:3px;transition:width .3s;}\n' +
        '#' + PREFIX + 'progress-meta{font-size:13px;color:#8c8c8c;}\n' +
        '#' + PREFIX + 'log{background:#fafafa;border:1px solid #f0f0f0;border-radius:4px;padding:12px;margin-top:12px;' +
        'font-family:Consolas,Monaco,monospace;font-size:12px;line-height:1.7;color:#595959;height:140px;overflow:auto;}\n' +
        '#' + PREFIX + 'logline{white-space:pre-wrap;}\n' +
        '#' + PREFIX + 'logline.err{color:#ff4d4f;}\n' +
        '#' + PREFIX + 'logline.ok{color:#52c41a;}\n' +
        '#' + PREFIX + 'logline.warn{color:#faad14;}\n' +
        '#' + PREFIX + 'empty{padding:16px;color:#8c8c8c;font-size:13px;text-align:center;}\n';

    /* ---- 主色取样：ZStack 支持"主题外观"自定义，硬编码颜色会与平台不一致 ---- */
    function hexToRgb(hex) {
        var m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(String(hex).trim());
        return m ? { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) } : null;
    }

    function rgbToHex(c) {
        function h(n) {
            var s = Math.max(0, Math.min(255, Math.round(n))).toString(16);
            return s.length === 1 ? '0' + s : s;
        }
        return '#' + h(c.r) + h(c.g) + h(c.b);
    }

    function mixColor(hex, target, ratio) {
        var a = hexToRgb(hex), b = hexToRgb(target);
        if (!a || !b) return hex;
        return rgbToHex({
            r: a.r + (b.r - a.r) * ratio,
            g: a.g + (b.g - a.g) * ratio,
            b: a.b + (b.b - a.b) * ratio
        });
    }

    // 把 "rgb(r,g,b)" 归一化为 hex；灰色/过亮/过暗的都不算主色，返回 null
    function toVividHex(colorStr) {
        if (!colorStr) return null;
        var m = /rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)/.exec(colorStr);
        if (!m) return null;
        var r = +m[1], g = +m[2], b = +m[3];
        var max = Math.max(r, g, b), min = Math.min(r, g, b);
        if (max === min) return null;                       // 纯灰
        var l = (max + min) / 510;
        var sat = (max - min) / (l > 0.5 ? (510 - max - min) : (max + min));
        if (sat < 0.35 || l < 0.22 || l > 0.78) return null; // 排除浅色选中底色、近黑近白
        return rgbToHex({ r: r, g: g, b: b });
    }

    function detectPrimaryColor() {
        try {
            var rs = window.getComputedStyle(document.documentElement);
            var varNames = ['--primary-color', '--primaryColor', '--color-primary', '--theme-color',
                '--brand-color', '--ant-primary-color', '--el-color-primary'];
            for (var i = 0; i < varNames.length; i++) {
                var v = toVividHex(rs.getPropertyValue(varNames[i]));
                if (v) return v;
            }
            // 取样页面上已渲染的主色控件：主按钮优先，其次顶栏
            var selectors = [
                '.ant-btn-primary', 'button[class*="primary"]', '[class*="btn-primary"]',
                '[class*="header-bar"]', '[class*="top-bar"]', '[class*="topBar"]',
                '[class*="navbar"]', 'header', '[class*="ant-menu-item-selected"]'
            ];
            for (var j = 0; j < selectors.length; j++) {
                var node = document.querySelector(selectors[j]);
                if (!node || !node.offsetWidth) continue;
                var c = toVividHex(window.getComputedStyle(node).backgroundColor);
                if (c) return c;
            }
        } catch (e) { /* 取样失败则用兜底色 */ }
        return '#7c3aed';   // ZStack 默认紫（兜底）
    }

    var themeApplied = null;
    function applyTheme() {
        try {
            var primary = detectPrimaryColor();
            if (primary === themeApplied) return;
            themeApplied = primary;
            var s = document.documentElement.style;
            s.setProperty('--zsbi-primary', primary);
            s.setProperty('--zsbi-primary-hover', mixColor(primary, '#000000', 0.18));
            s.setProperty('--zsbi-primary-light', mixColor(primary, '#ffffff', 0.94));
            s.setProperty('--zsbi-primary-border', mixColor(primary, '#ffffff', 0.7));
        } catch (e) { /* 忽略 */ }
    }

    var stylesInjected = false;
    function injectStyles() {
        if (stylesInjected || document.getElementById(PREFIX + 'styles')) return;
        var host = document.head || document.documentElement;
        if (!host) return;
        var cssEl = document.createElement('style');
        cssEl.id = PREFIX + 'styles';
        cssEl.textContent = STYLES;
        host.appendChild(cssEl);
        stylesInjected = true;
    }

    // 持有的 UI 节点引用：节点被 SPA 摘除后 getElementById 会找不到，必须靠引用重挂
    var uiRefs = { fab: null, panel: null, defPass: null };

    function buildUI() {
        applyTheme();   // 先取平台主色，再渲染，避免闪色
        injectStyles();
        // 悬浮按钮
        var fab = el('button', { id: PREFIX + 'fab', title: 'ZStack 批量账户导入' }, ['批量导入']);
        fab.addEventListener('click', function () { openPanel(); });
        uiRefs.fab = fab;

        // 面板
        var panel = el('div', { id: PREFIX + 'panel' });
        uiRefs.panel = panel;

        var header = el('div', { class: PREFIX + 'h' }, []);
        header.id = PREFIX + 'header';
        header.appendChild(el('div', { class: 'title' }, ['ZStack 批量账户导入']));
        var closeBtn = el('button', { id: PREFIX + 'close' }, ['✕']);
        closeBtn.addEventListener('click', function () { closePanel(); });
        header.appendChild(closeBtn);

        // 会话条
        var sessionBar = el('div', { id: PREFIX + 'sessionbar' });
        sessionBar.id = PREFIX + 'sessionbar';
        sessionBar.appendChild(el('span', {}, ['会话:']));
        var st = el('span', { id: PREFIX + 'session-status', class: PREFIX + 'status-badge warn' }, ['等待捕获…']);
        sessionBar.appendChild(st);
        var input = el('input', {
            id: PREFIX + 'session-value', type: 'text', placeholder: '手动粘贴 x-session-id（可选，从浏览器开发者工具 Network 复制）'
        });
        sessionBar.appendChild(input);
        var applyBtn = el('button', { class: PREFIX + 'btn secondary' }, ['应用']);
        applyBtn.addEventListener('click', function () {
            var v = input.value.trim();
            if (/^[0-9a-f]{32}$/.test(v)) { adoptSession(v); }
            else log('无效的 session id（应为 32 位 hex）', 'err');
        });
        sessionBar.appendChild(applyBtn);

        var tip = el('div', { id: PREFIX + 'session-tip' },
            ['如需自动捕获：保持页面已登录，脚本会从页面自身的请求中自动读取会话。若未捕获，请刷新页面或点击任意菜单后再试。']);
        sessionBar.appendChild(tip);

        // 内容区
        var body = el('div', { id: PREFIX + 'body' });
        body.id = PREFIX + 'body';

        var drop = el('div', { id: PREFIX + 'drop' });
        drop.appendChild(el('b', {}, ['点击或拖拽上传账户文件']));
        drop.appendChild(el('small', {}, ['支持 .csv / .txt / .xls / .xlsx；字段：学号, 姓名, 密码, 班级（密码留空默认 ' + DEFAULT_PASSWORD + '；班级作为计费价目名称，留空用默认价目）']));
        var fileInput = el('input', { type: 'file', accept: '.csv,.txt,.xls,.xlsx' });
        fileInput.style.display = 'none';
        drop.addEventListener('click', function () { fileInput.click(); });
        drop.appendChild(fileInput);

        var controls = el('div', { id: PREFIX + 'controls' });
        controls.id = PREFIX + 'controls';

        var dlTmpl = el('button', { class: PREFIX + 'btn secondary' }, ['下载数据导入模板']);
        dlTmpl.addEventListener('click', function () {
            download('userimport.csv',
                '\uFEFF学号,姓名,密码,班级\n' +
                '202522050969,张三,,一班\n' +
                '202522050970,李四,Abc@123456,二班\n',
                'text/csv;charset=utf-8');
        });
        controls.appendChild(dlTmpl);

        var defPassLabel = el('label', {}, ['默认密码:']);
        var defPass = el('input', {
            id: PREFIX + 'defpass', type: 'text', placeholder: DEFAULT_PASSWORD,
            title: '文件中密码留空时使用此值，留空则为 ' + DEFAULT_PASSWORD
        });
        uiRefs.defPass = defPass;
        controls.appendChild(defPassLabel);
        controls.appendChild(defPass);

        var runBtn = el('button', { id: PREFIX + 'run', class: PREFIX + 'btn' }, ['开始导入']);
        runBtn.addEventListener('click', runImport);
        var stopBtn = el('button', { id: PREFIX + 'stop', class: PREFIX + 'btn danger' }, ['停止']);
        stopBtn.style.display = 'none';
        stopBtn.addEventListener('click', function () { STATE.stopRequested = true; log('正在停止…'); });
        controls.appendChild(runBtn);
        controls.appendChild(stopBtn);

        var exportBtn = el('button', { id: PREFIX + 'export', class: PREFIX + 'btn secondary' }, ['导出结果']);
        exportBtn.addEventListener('click', exportResults);
        controls.appendChild(exportBtn);

        var previewLabel = el('div', { id: PREFIX + 'preview-label' }, ['数据预览']);
        var tablewrap = el('div', { id: PREFIX + 'tablewrap' });
        tablewrap.id = PREFIX + 'tablewrap';
        var progressArea = el('div', {});
        progressArea.appendChild(el('div', { id: PREFIX + 'bar' }, []));
        progressArea.appendChild(el('div', { id: PREFIX + 'progress-meta', class: PREFIX + 'progress-meta' }, ['尚未开始']));
        var logbox = el('div', { id: PREFIX + 'log' });
        logbox.id = PREFIX + 'log';

        body.appendChild(drop);
        body.appendChild(controls);
        body.appendChild(el('div', { class: PREFIX + 'template-samples' }, [
            '模板字段：',
            el('code', {}, '学号, 姓名, 密码, 班级'),
            '　学号必填（写入账户名称）；姓名写入账户简介；密码留空默认 ' + DEFAULT_PASSWORD + '；班级作为计费价目名称（不存在则自动创建，留空使用默认计费价目）。',
        ]));
        body.appendChild(previewLabel);
        body.appendChild(tablewrap);
        body.appendChild(progressArea);
        body.appendChild(logbox);

        panel.appendChild(header);
        panel.appendChild(sessionBar);
        panel.appendChild(body);

        document.body.appendChild(fab);
        document.body.appendChild(panel);

        // 文件事件
        fileInput.addEventListener('change', function (ev) {
            handleFile(ev.target.files[0]);
            ev.target.value = '';
        });
        ['dragover', 'drop'].forEach(function (evName) {
            drop.addEventListener(evName, function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                if (evName === 'drop') {
                    var f = ev.dataTransfer.files[0];
                    if (f) handleFile(f);
                }
            });
        });
        ['dragenter', 'dragleave'].forEach(function (evName) {
            drop.addEventListener(evName, function (ev) { ev.preventDefault(); });
        });

        // 统一密码变化后重算（缺密码的行会用这个值兜底）
        defPass.addEventListener('input', function () {
            if (STATE.rows.length) rebuildFromRows();
        });

        panel._open = false;
    }

    // 读取"统一密码"输入框当前值（用引用，避免 SPA 重渲染后查不到）
    function getFallbackPassword() {
        return (uiRefs.defPass && uiRefs.defPass.value) || '';
    }

    function handleFile(file) {
        log('读取文件：' + file.name);
        parseFile(file, function (data) {
            try {
                if (data.kind === 'txt') {
                    // TXT：每行一个学号；姓名/班级留空；密码用默认值
                    var names = data.text.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
                    STATE.rows = names.map(function (n, i) {
                        return {
                            name: n, description: '', className: '',
                            password: getFallbackPassword() || DEFAULT_PASSWORD,
                            line: i + 1, _idx: i
                        };
                    });
                } else {
                    var built = buildRows(data.parsed, getFallbackPassword());
                    STATE.rows = built.rows;
                    if (built.ignored.length) {
                        // 明确告知被忽略的列，避免"字段被静默丢掉"
                        log('已忽略非表单字段：' + built.ignored.join('、'), 'warn');
                    }
                }
                detectDuplicates(STATE.rows);
                rebuildFromRows();
                log('解析完成，共 ' + STATE.rows.length + ' 行');
            } catch (err) {
                log('解析错误：' + err.message, 'err');
            }
        }, function (msg) { log(msg, 'err'); });
    }

    // 统一的"行 -> 结果"构建：无效行为 invalid，有效行携带提示信息(warn)
    function buildResults() {
        return STATE.rows.map(function (r) {
            var errs = validateRow(r);
            return {
                row: r,
                errs: errs,
                status: errs.length ? 'invalid' : 'pending',
                message: errs.join('; ')
            };
        });
    }

    function rebuildFromRows() {
        var previewLabel = document.getElementById(PREFIX + 'preview-label');
        previewLabel.textContent = '数据预览（共 ' + STATE.rows.length + ' 行）';
        STATE.results = buildResults();
        renderResults();
    }

    function renderResults() {
        var wrap = document.getElementById(PREFIX + 'tablewrap');
        if (!wrap) return;
        wrap.innerHTML = '';
        if (!STATE.results.length) { wrap.appendChild(el('div', { class: PREFIX + 'empty' }, ['暂无数据'])); return; }
        // 列与模板字段一致：学号 / 姓名 / 密码 / 班级
        var cols = ['#', '学号', '姓名', '密码', '班级', '状态/错误'];
        var table = el('table', { id: PREFIX + 'table' });
        var thead = el('thead');
        var trh = el('tr');
        cols.forEach(function (c) { trh.appendChild(el('th', {}, [c])); });
        thead.appendChild(trh);
        table.appendChild(thead);

        var tbody = el('tbody');
        var maxView = 50;
        var total = STATE.results.length;
        STATE.results.slice(0, maxView).forEach(function (res) {
            var r = res.row;
            var tr = el('tr', { class: res.status + (res.row._dup ? ' invalid' : '') });
            tr.appendChild(el('td', {}, [String(r.line)]));
            tr.appendChild(el('td', {}, [r.name || '-']));
            tr.appendChild(el('td', {}, [r.description || '-']));
            tr.appendChild(el('td', {}, [r.password ? '••••••' : '-']));
            tr.appendChild(el('td', {}, [r.className || '-']));
            var statusText = res.status === 'pending' ? '待导入' :
                res.status === 'invalid' ? res.message + (r._dup ? ' / 学号重复' : '') :
                res.status === 'success' ? ('成功' + (res.bindMsg ? '（' + res.bindMsg + '）' : '')) :
                res.status === 'failed' ? '失败：' + res.message :
                res.status === 'running' ? '导入中…' : res.status;
            tr.appendChild(el('td', {}, [statusText]));
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        wrap.appendChild(table);
        if (total > maxView) {
            wrap.appendChild(el('div', { class: PREFIX + 'empty' }, ['… 仅显示前 ' + maxView + ' 行（共 ' + total + ' 行），完整结果可在导入后导出']));
        }
        // 汇总
        var ok = STATE.results.filter(function (x) { return x.status === 'pending'; }).length;
        var bad = STATE.results.filter(function (x) { return x.status === 'invalid'; }).length;
        var inProg = STATE.results.filter(function (x) { return x.status === 'running' || x.status === 'success' || x.status === 'failed'; }).length;
        var sum = el('div', { id: PREFIX + 'summary' },
            ['可导入 ' + ok + ' 行' + (bad ? '，无效/重复 ' + bad + ' 行' : '') + (inProg ? '，已处理 ' + inProg + ' 行' : '')]);
        wrap.appendChild(sum);
    }

    function updateProgress() {
        var p = STATE.progress;
        if (!p || !p.total) return;
        var barFill = document.querySelector('#' + PREFIX + 'bar > div');
        if (!barFill) {
            barFill = el('div', {});
            document.getElementById(PREFIX + 'bar').appendChild(barFill);
        }
        var pct = Math.round(p.done / p.total * 100);
        barFill.style.width = pct + '%';
        var meta = document.getElementById(PREFIX + 'progress-meta');
        meta.textContent = '进度 ' + p.done + '/' + p.total + '（成功 ' + p.ok + '，失败 ' + p.fail + '）';
    }

    function setUiBusy(busy) {
        STATE.busy = busy;
        var run = document.getElementById(PREFIX + 'run');
        var stop = document.getElementById(PREFIX + 'stop');
        var exportBtn = document.getElementById(PREFIX + 'export');
        if (run) run.disabled = busy;
        if (stop) stop.style.display = busy ? '' : 'none';
        if (exportBtn) exportBtn.disabled = busy;
        if (busy) { if (stop) stop.style.display = ''; }
    }

    function exportResults() {
        if (!STATE.results || !STATE.results.length) { log('暂无结果可导出', 'warn'); return; }
        var lines = ['学号,姓名,密码,班级,状态,信息'];
        STATE.results.forEach(function (res) {
            var r = res.row;
            lines.push([r.name, r.description || '', r.password, r.className || '', res.status, res.message].map(csvEscape).join(','));
        });
        download('zstack_import_result.csv', '\uFEFF' + lines.join('\r\n'), 'text/csv;charset=utf-8');
        log('已导出结果 CSV');
    }

    function openPanel() {
        applyTheme();   // 此时页面已渲染完整，取样更准
        if (!STATE.sessionId) scanStorageForSession();
        verifyMount();
        if (uiRefs.panel) uiRefs.panel.classList.add(PREFIX + 'open');
    }
    function closePanel() {
        if (uiRefs.panel) uiRefs.panel.classList.remove(PREFIX + 'open');
    }

    /* ======================================================================
     * 9. 启动
     *    ZStack 前端是 SPA：脚本在 document-start 执行时 body 尚未渲染，
     *    渲染过程中还可能重建 body 内容把我们的节点清掉。
     *    因此 UI 采用「挂载 + 自愈」策略：被移除就自动挂回去。
     * ====================================================================== */
    var mounted = false;
    var domObserver = null;

    function reportFatal(err) {
        try {
            var box = document.createElement('div');
            box.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647;background:#c0392b;color:#fff;' +
                'padding:10px 14px;border-radius:8px;font:12px/1.6 Consolas,monospace;max-width:560px;white-space:pre-wrap;';
            box.textContent = '[ZStack批量导入] 脚本出错：' + (err && err.message ? err.message : err);
            (document.body || document.documentElement).appendChild(box);
        } catch (e) { /* 连报错都失败就只能放弃 */ }
        try { console.error('[ZStack批量导入] 出错：', err); } catch (e) { }
    }

    // 把被 SPA 清掉的节点挂回去（只移动已有节点，不重建，避免状态丢失）
    function verifyMount() {
        if (!mounted) return;
        try {
            var root = document.body || document.documentElement;
            if (!root) return;
            // 用引用而非 getElementById：被摘除的节点已不在文档里，按 id 查不到
            if (uiRefs.fab && !document.contains(uiRefs.fab)) root.appendChild(uiRefs.fab);
            if (uiRefs.panel && !document.contains(uiRefs.panel)) root.appendChild(uiRefs.panel);
            // 样式被移除时重新注入（重渲染可能连 <style> 一起清掉）
            if (!document.getElementById(PREFIX + 'styles')) { stylesInjected = false; injectStyles(); }
            if (!STATE.sessionId) scanStorageForSession();   // 会话仍未捕获时持续尝试
        } catch (e) { /* 忽略 */ }
    }

    function watchDom() {
        try {
            if (!domObserver && typeof MutationObserver !== 'undefined' && document.documentElement) {
                domObserver = new MutationObserver(function () { verifyMount(); });
                domObserver.observe(document.documentElement, { childList: true, subtree: true });
            }
        } catch (e) { /* 忽略 */ }
        // 兜底轮询：覆盖 SPA 早期频繁重渲染与懒加载场景
        var ticks = 0;
        var timer = setInterval(function () {
            verifyMount();
            if (++ticks >= 40) clearInterval(timer);
        }, 1500);
    }

    function boot() {
        try {
            if (mounted) return;
            if (!document.body) { setTimeout(boot, 200); return; }   // body 未就绪，稍后再试
            if (uiRefs.panel) { mounted = true; verifyMount(); watchDom(); return; }
            buildUI();
            mounted = true;
            watchDom();
            log('ZStack 批量账户导入已加载。点击右下角「批量导入」开始。');
            log('SHA-512 自检：' + (HASH_OK ? '通过 ✓' : '失败 ✗（导入已被禁用）'), HASH_OK ? 'ok' : 'err');
            console.log('[ZStack批量导入] 已加载。SHA-512 自检:', HASH_OK ? '通过' : '失败');
        } catch (err) {
            reportFatal(err);
        }
    }

    // 会话捕获必须尽早安装：页面加载过程中就会发出带 x-session-id 的请求
    try { startSessionCapture(); } catch (e) { reportFatal(e); }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
    else boot();
    window.addEventListener('load', function () { setTimeout(boot, 300); });
    setTimeout(boot, 2500);   // 兜底：应对极端懒渲染
})();