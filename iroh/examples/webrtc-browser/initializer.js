// Trunk initializer — captures wasm-bindgen exports so inline JS can use them.
// See https://trunkrs.dev/assets/#initializer
export default function initializer() {
    return {
        onSuccess: (wasm) => {
            window.__wasm = wasm;
        },
    };
}
