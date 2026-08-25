import js from "@eslint/js";
import pluginVue from "eslint-plugin-vue";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "src-tauri/target/**", "src-tauri/gen/**", "node_modules/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...pluginVue.configs["flat/essential"],
  { files: ["src/**/*.vue"], languageOptions: { parserOptions: { parser: tseslint.parser } } },
  { files: ["src/**/*.{ts,vue}"], languageOptions: { globals: { window: "readonly", crypto: "readonly", setTimeout: "readonly", structuredClone: "readonly" } }, rules: { "vue/multi-word-component-names": "off", "vue/max-attributes-per-line": "off", "vue/html-self-closing": "off", "vue/singleline-html-element-content-newline": "off", "vue/multiline-html-element-content-newline": "off", "@typescript-eslint/no-explicit-any": "error" } }
);
