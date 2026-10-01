<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { editorText, restoreFileText } from "../services/fileEditing";
const props = defineProps<{ modelValue: string; original: string; disabled?: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [value: string] }>();
const input = ref<{ value: string; scrollTop: number; focus: () => void }>();
const gutter = ref<{ scrollTop: number }>();
const text = computed(() => editorText(props.modelValue));
const numbers = computed(() => Array.from({ length: text.value.split("\n").length }, (_, i) => i + 1).join("\n"));
function update() { if (input.value) emit('update:modelValue', restoreFileText(input.value.value, props.original)); }
function scroll() { if (gutter.value && input.value) gutter.value.scrollTop = input.value.scrollTop; }
onMounted(() => input.value?.focus());
</script>

<template>
  <div class="file-text-editor">
    <pre ref="gutter" aria-hidden="true">{{ numbers }}</pre>
    <textarea ref="input" :value="text" :disabled="disabled" aria-label="Bestandsinhoud bewerken" wrap="off" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" @input="update" @scroll="scroll"></textarea>
  </div>
</template>

<style scoped>
.file-text-editor { display:flex;flex:1 1 auto;min-height:0;height:420px;max-height:420px;min-width:0;overflow:hidden;background:#15221d;border-radius:8px;color:#e6f0eb; }
.file-text-editor pre,.file-text-editor textarea { box-sizing:border-box;margin:0;padding:14px;font:13px/1.55 ui-monospace,Consolas,monospace;tab-size:4; }
.file-text-editor pre { flex:none;min-width:4ch;overflow:hidden;text-align:right;background:#101d18;color:#9cb2a7;border-right:1px solid #30423a;user-select:none; }
.file-text-editor textarea { flex:1;min-width:0;width:100%;border:0;border-radius:0;background:#15221d;color:#e6f0eb;resize:none;white-space:pre;overflow:auto;overscroll-behavior:contain; }
.file-text-editor textarea:focus { outline:2px solid #6abfa1;outline-offset:-2px; }
.preview-modal.fullscreen .file-text-editor { flex:1 1 0;max-height:none;height:auto; }
</style>
