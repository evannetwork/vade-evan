let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;
const { TextEncoder, TextDecoder } = require(`util`);

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let WASM_VECTOR_LEN = 0;

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

let cachedFloat64Memory0 = null;

function getFloat64Memory0() {
    if (cachedFloat64Memory0 === null || cachedFloat64Memory0.byteLength === 0) {
        cachedFloat64Memory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachedFloat64Memory0;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {
        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            if (--state.cnt === 0) {
                wasm.__wbindgen_export_2.get(state.dtor)(a, state.b);

            } else {
                state.a = a;
            }
        }
    };
    real.original = state;

    return real;
}
function __wbg_adapter_34(arg0, arg1) {
    wasm._dyn_core__ops__function__FnMut_____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h1f17024f08301b86(arg0, arg1);
}

function __wbg_adapter_37(arg0, arg1, arg2) {
    wasm._dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hc79d0bc19b996f8b(arg0, arg1, addHeapObject(arg2));
}

/**
*/
module.exports.set_panic_hook = function() {
    wasm.set_panic_hook();
};

/**
* @param {string} log_level
*/
module.exports.set_log_level = function(log_level) {
    const ptr0 = passStringToWasm0(log_level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.set_log_level(ptr0, len0);
};

/**
* @param {string} did_or_method
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.did_resolve = function(did_or_method, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.did_resolve(ptr0, len0, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.did_create = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.did_create(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.did_update = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.did_update(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} custom_func_name
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.run_custom_function = function(did_or_method, custom_func_name, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(custom_func_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.run_custom_function(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_create_credential_offer = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_create_credential_offer(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_create_credential_proposal = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_create_credential_proposal(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_create_credential_schema = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_create_credential_schema(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_create_revocation_registry_definition = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_create_revocation_registry_definition(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_update_revocation_registry = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_update_revocation_registry(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_issue_credential = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_issue_credential(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_finish_credential = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_finish_credential(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_present_proof = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_present_proof(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_request_credential = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_request_credential(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_request_proof = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_request_proof(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_revoke_credential = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_revoke_credential(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.vc_zkp_verify_proof = function(did_or_method, options, payload, config) {
    const ptr0 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.vc_zkp_verify_proof(ptr0, len0, ptr1, len1, ptr2, len2, addHeapObject(config));
    return takeObject(ret);
};

/**
* @returns {Promise<string | undefined>}
*/
module.exports.get_version_info = function() {
    const ret = wasm.get_version_info();
    return takeObject(ret);
};

/**
* @param {string | undefined} bbs_public_key
* @param {string | undefined} signing_key
* @param {string | undefined} service_endpoint
* @returns {Promise<string | undefined>}
*/
module.exports.helper_did_create = function(bbs_public_key, signing_key, service_endpoint) {
    var ptr0 = isLikeNone(bbs_public_key) ? 0 : passStringToWasm0(bbs_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(signing_key) ? 0 : passStringToWasm0(signing_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(service_endpoint) ? 0 : passStringToWasm0(service_endpoint, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.helper_did_create(ptr0, len0, ptr1, len1, ptr2, len2);
    return takeObject(ret);
};

/**
* @param {string} did
* @param {string} operation
* @param {string} update_key
* @param {string} payload
* @returns {Promise<string | undefined>}
*/
module.exports.helper_did_update = function(did, operation, update_key, payload) {
    const ptr0 = passStringToWasm0(did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(operation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(update_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.helper_did_update(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return takeObject(ret);
};

/**
* @param {string} schema_did
* @param {boolean} use_valid_until
* @param {string} issuer_did
* @param {string | undefined} subject_did
* @returns {Promise<string>}
*/
module.exports.helper_create_credential_offer = function(schema_did, use_valid_until, issuer_did, subject_did) {
    const ptr0 = passStringToWasm0(schema_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(issuer_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(subject_did) ? 0 : passStringToWasm0(subject_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.helper_create_credential_offer(ptr0, len0, use_valid_until, ptr1, len1, ptr2, len2);
    return takeObject(ret);
};

/**
* @param {string} issuer_public_key
* @param {string} bbs_secret
* @param {string} credential_values
* @param {string} credential_offer
* @param {string} credential_schema
* @returns {Promise<string>}
*/
module.exports.helper_create_credential_request = function(issuer_public_key, bbs_secret, credential_values, credential_offer, credential_schema) {
    const ptr0 = passStringToWasm0(issuer_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(bbs_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(credential_values, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(credential_offer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(credential_schema, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.helper_create_credential_request(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    return takeObject(ret);
};

/**
* @param {string} credential
* @param {string} master_secret
* @returns {Promise<string>}
*/
module.exports.helper_verify_credential = function(credential, master_secret) {
    const ptr0 = passStringToWasm0(credential, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(master_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.helper_verify_credential(ptr0, len0, ptr1, len1);
    return takeObject(ret);
};

/**
* @param {string} func_name
* @param {string} did_or_method
* @param {string} options
* @param {string} payload
* @param {string} custom_func_name
* @param {any} config
* @returns {Promise<string>}
*/
module.exports.execute_vade = function(func_name, did_or_method, options, payload, custom_func_name, config) {
    const ptr0 = passStringToWasm0(func_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(did_or_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(options, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(custom_func_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.execute_vade(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, addHeapObject(config));
    return takeObject(ret);
};

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
function __wbg_adapter_169(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures__invoke2_mut__h7f2b091694fb424e(arg0, arg1, addHeapObject(arg2), addHeapObject(arg3));
}

/**
* Indicates the status returned from `PoKOfSignatureProof`
*/
module.exports.PoKOfSignatureProofStatus = Object.freeze({
/**
* The proof verified
*/
Success:0,"0":"Success",
/**
* The proof failed because the signature proof of knowledge failed
*/
BadSignature:1,"1":"BadSignature",
/**
* The proof failed because a hidden message was invalid when the proof was created
*/
BadHiddenMessage:2,"2":"BadHiddenMessage",
/**
* The proof failed because a revealed message was invalid
*/
BadRevealedMessage:3,"3":"BadRevealedMessage", });

module.exports.__wbindgen_string_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

module.exports.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

module.exports.__wbindgen_is_undefined = function(arg0) {
    const ret = getObject(arg0) === undefined;
    return ret;
};

module.exports.__wbindgen_object_clone_ref = function(arg0) {
    const ret = getObject(arg0);
    return addHeapObject(ret);
};

module.exports.__wbindgen_is_object = function(arg0) {
    const val = getObject(arg0);
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
};

module.exports.__wbindgen_jsval_loose_eq = function(arg0, arg1) {
    const ret = getObject(arg0) == getObject(arg1);
    return ret;
};

module.exports.__wbindgen_boolean_get = function(arg0) {
    const v = getObject(arg0);
    const ret = typeof(v) === 'boolean' ? (v ? 1 : 0) : 2;
    return ret;
};

module.exports.__wbindgen_number_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getFloat64Memory0()[arg0 / 8 + 1] = isLikeNone(ret) ? 0 : ret;
    getInt32Memory0()[arg0 / 4 + 0] = !isLikeNone(ret);
};

module.exports.__wbg_String_91fba7ded13ba54c = function(arg0, arg1) {
    const ret = String(getObject(arg1));
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbindgen_error_new = function(arg0, arg1) {
    const ret = new Error(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_new_abda76e883ba8a5f = function() {
    const ret = new Error();
    return addHeapObject(ret);
};

module.exports.__wbg_stack_658279fe44541cf6 = function(arg0, arg1) {
    const ret = getObject(arg1).stack;
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbg_error_f851667af71bcfc6 = function(arg0, arg1) {
    try {
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(arg0, arg1);
    }
};

module.exports.__wbindgen_cb_drop = function(arg0) {
    const obj = takeObject(arg0).original;
    if (obj.cnt-- == 1) {
        obj.a = 0;
        return true;
    }
    const ret = false;
    return ret;
};

module.exports.__wbg_clearTimeout_76877dbc010e786d = function(arg0) {
    const ret = clearTimeout(takeObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_setTimeout_75cb9b6991a4031d = function() { return handleError(function (arg0, arg1) {
    const ret = setTimeout(getObject(arg0), arg1);
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbindgen_is_string = function(arg0) {
    const ret = typeof(getObject(arg0)) === 'string';
    return ret;
};

module.exports.__wbg_randomFillSync_6894564c2c334c42 = function() { return handleError(function (arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
}, arguments) };

module.exports.__wbg_getRandomValues_805f1c3d65988a5a = function() { return handleError(function (arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
}, arguments) };

module.exports.__wbg_crypto_e1d53a1d73fb10b8 = function(arg0) {
    const ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

module.exports.__wbg_process_038c26bf42b093f8 = function(arg0) {
    const ret = getObject(arg0).process;
    return addHeapObject(ret);
};

module.exports.__wbg_versions_ab37218d2f0b24a8 = function(arg0) {
    const ret = getObject(arg0).versions;
    return addHeapObject(ret);
};

module.exports.__wbg_node_080f4b19d15bc1fe = function(arg0) {
    const ret = getObject(arg0).node;
    return addHeapObject(ret);
};

module.exports.__wbg_msCrypto_6e7d3e1f92610cbb = function(arg0) {
    const ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

module.exports.__wbg_require_78a3dcfbdba9cbce = function() { return handleError(function () {
    const ret = module.require;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbindgen_is_function = function(arg0) {
    const ret = typeof(getObject(arg0)) === 'function';
    return ret;
};

module.exports.__wbg_fetch_3a1be51760e1f8eb = function(arg0) {
    const ret = fetch(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_self_7eede1f4488bf346 = function() { return handleError(function () {
    const ret = self.self;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_crypto_c909fb428dcbddb6 = function(arg0) {
    const ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

module.exports.__wbg_msCrypto_511eefefbfc70ae4 = function(arg0) {
    const ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
};

module.exports.__wbg_static_accessor_MODULE_ef3aa2eb251158a5 = function() {
    const ret = module;
    return addHeapObject(ret);
};

module.exports.__wbg_require_900d5c3984fe7703 = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
    return addHeapObject(ret);
};

module.exports.__wbg_getRandomValues_307049345d0bd88c = function(arg0) {
    const ret = getObject(arg0).getRandomValues;
    return addHeapObject(ret);
};

module.exports.__wbg_getRandomValues_cd175915511f705e = function(arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
};

module.exports.__wbg_randomFillSync_85b3f4c52c56c313 = function(arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
};

module.exports.__wbg_fetch_661ffba2a4f2519c = function(arg0, arg1) {
    const ret = getObject(arg0).fetch(getObject(arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_newwithstrandinit_c45f0dc6da26fd03 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = new Request(getStringFromWasm0(arg0, arg1), getObject(arg2));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_debug_7960d327fd96f71a = function(arg0, arg1, arg2, arg3) {
    console.debug(getObject(arg0), getObject(arg1), getObject(arg2), getObject(arg3));
};

module.exports.__wbg_error_fd84ca2a8a977774 = function(arg0, arg1, arg2, arg3) {
    console.error(getObject(arg0), getObject(arg1), getObject(arg2), getObject(arg3));
};

module.exports.__wbg_info_5566be377f5b52ae = function(arg0, arg1, arg2, arg3) {
    console.info(getObject(arg0), getObject(arg1), getObject(arg2), getObject(arg3));
};

module.exports.__wbg_log_7b690f184ae4519b = function(arg0, arg1, arg2, arg3) {
    console.log(getObject(arg0), getObject(arg1), getObject(arg2), getObject(arg3));
};

module.exports.__wbg_warn_48cbddced45e5414 = function(arg0, arg1, arg2, arg3) {
    console.warn(getObject(arg0), getObject(arg1), getObject(arg2), getObject(arg3));
};

module.exports.__wbg_instanceof_Response_fb3a4df648c1859b = function(arg0) {
    let result;
    try {
        result = getObject(arg0) instanceof Response;
    } catch {
        result = false;
    }
    const ret = result;
    return ret;
};

module.exports.__wbg_url_8ec2534cdfacb103 = function(arg0, arg1) {
    const ret = getObject(arg1).url;
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbg_status_d483a4ac847f380a = function(arg0) {
    const ret = getObject(arg0).status;
    return ret;
};

module.exports.__wbg_headers_6093927dc359903e = function(arg0) {
    const ret = getObject(arg0).headers;
    return addHeapObject(ret);
};

module.exports.__wbg_text_f61464d781b099f0 = function() { return handleError(function (arg0) {
    const ret = getObject(arg0).text();
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_new_f1c3a9c2533a55b8 = function() { return handleError(function () {
    const ret = new Headers();
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_append_1be1d651f9ecf2eb = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
    getObject(arg0).append(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
}, arguments) };

module.exports.__wbg_get_27fe3dac1c4d0224 = function(arg0, arg1) {
    const ret = getObject(arg0)[arg1 >>> 0];
    return addHeapObject(ret);
};

module.exports.__wbg_length_e498fbc24f9c1d4f = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbg_newnoargs_2b8b6bd7753c76ba = function(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_next_b7d530c04fd8b217 = function(arg0) {
    const ret = getObject(arg0).next;
    return addHeapObject(ret);
};

module.exports.__wbg_next_88560ec06a094dea = function() { return handleError(function (arg0) {
    const ret = getObject(arg0).next();
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_done_1ebec03bbd919843 = function(arg0) {
    const ret = getObject(arg0).done;
    return ret;
};

module.exports.__wbg_value_6ac8da5cc5b3efda = function(arg0) {
    const ret = getObject(arg0).value;
    return addHeapObject(ret);
};

module.exports.__wbg_iterator_55f114446221aa5a = function() {
    const ret = Symbol.iterator;
    return addHeapObject(ret);
};

module.exports.__wbg_get_baf4855f9a986186 = function() { return handleError(function (arg0, arg1) {
    const ret = Reflect.get(getObject(arg0), getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_call_95d1ea488d03e4e8 = function() { return handleError(function (arg0, arg1) {
    const ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_new_f9876326328f45ed = function() {
    const ret = new Object();
    return addHeapObject(ret);
};

module.exports.__wbg_self_e7c1f827057f6584 = function() { return handleError(function () {
    const ret = self.self;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_window_a09ec664e14b1b81 = function() { return handleError(function () {
    const ret = window.window;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_globalThis_87cbb8506fecf3a9 = function() { return handleError(function () {
    const ret = globalThis.globalThis;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_global_c85a9259e621f3db = function() { return handleError(function () {
    const ret = global.global;
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_instanceof_ArrayBuffer_a69f02ee4c4f5065 = function(arg0) {
    let result;
    try {
        result = getObject(arg0) instanceof ArrayBuffer;
    } catch {
        result = false;
    }
    const ret = result;
    return ret;
};

module.exports.__wbg_call_9495de66fdbe016b = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_new0_25059e40b1c02766 = function() {
    const ret = new Date();
    return addHeapObject(ret);
};

module.exports.__wbg_toISOString_8e31986cf23150ba = function(arg0) {
    const ret = getObject(arg0).toISOString();
    return addHeapObject(ret);
};

module.exports.__wbg_entries_4e1315b774245952 = function(arg0) {
    const ret = Object.entries(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_toString_74f30a40ad3d8cd1 = function(arg0) {
    const ret = getObject(arg0).toString();
    return addHeapObject(ret);
};

module.exports.__wbg_new_9d3a9ce4282a18a8 = function(arg0, arg1) {
    try {
        var state0 = {a: arg0, b: arg1};
        var cb0 = (arg0, arg1) => {
            const a = state0.a;
            state0.a = 0;
            try {
                return __wbg_adapter_169(a, state0.b, arg0, arg1);
            } finally {
                state0.a = a;
            }
        };
        const ret = new Promise(cb0);
        return addHeapObject(ret);
    } finally {
        state0.a = state0.b = 0;
    }
};

module.exports.__wbg_resolve_fd40f858d9db1a04 = function(arg0) {
    const ret = Promise.resolve(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_then_ec5db6d509eb475f = function(arg0, arg1) {
    const ret = getObject(arg0).then(getObject(arg1));
    return addHeapObject(ret);
};

module.exports.__wbg_then_f753623316e2873a = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).then(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
};

module.exports.__wbg_buffer_cf65c07de34b9a08 = function(arg0) {
    const ret = getObject(arg0).buffer;
    return addHeapObject(ret);
};

module.exports.__wbg_newwithbyteoffsetandlength_9fb2f11355ecadf5 = function(arg0, arg1, arg2) {
    const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_new_537b7341ce90bb31 = function(arg0) {
    const ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_set_17499e8aa4003ebd = function(arg0, arg1, arg2) {
    getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

module.exports.__wbg_length_27a2afe8ab42b09f = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbg_instanceof_Uint8Array_01cebe79ca606cca = function(arg0) {
    let result;
    try {
        result = getObject(arg0) instanceof Uint8Array;
    } catch {
        result = false;
    }
    const ret = result;
    return ret;
};

module.exports.__wbg_newwithlength_b56c882b57805732 = function(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_subarray_7526649b91a252a6 = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_has_3feea89d34bd7ad5 = function() { return handleError(function (arg0, arg1) {
    const ret = Reflect.has(getObject(arg0), getObject(arg1));
    return ret;
}, arguments) };

module.exports.__wbg_set_6aa458a4ebdb65cb = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = Reflect.set(getObject(arg0), getObject(arg1), getObject(arg2));
    return ret;
}, arguments) };

module.exports.__wbg_stringify_029a979dfb73aa17 = function() { return handleError(function (arg0) {
    const ret = JSON.stringify(getObject(arg0));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbindgen_debug_string = function(arg0, arg1) {
    const ret = debugString(getObject(arg1));
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

module.exports.__wbindgen_memory = function() {
    const ret = wasm.memory;
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper2018 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 547, __wbg_adapter_34);
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper3851 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 1042, __wbg_adapter_37);
    return addHeapObject(ret);
};

const path = require('path').join(__dirname, 'vade_evan_bg.wasm');
const bytes = require('fs').readFileSync(path);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
wasm = wasmInstance.exports;
module.exports.__wasm = wasm;

