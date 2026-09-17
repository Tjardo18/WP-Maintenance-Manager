<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { Maximize2, Minimize2, Trash2, X } from "@lucide/vue";
import type { FilePreview } from "../types";
import { highlightPreviewContent, previewSyntax } from "../services/fileSyntax";
import { formatDate } from "../utils/format";

const props = withDefaults(defineProps<{ preview: FilePreview; defaultFullscreen?: boolean }>(), {
  defaultFullscreen: false,
});
const emit = defineEmits<{ close: []; delete: [] }>();

const canDelete = computed(() => props.preview.finding.checksumStatus === "unexpected");
const syntax = computed(() => previewSyntax(props.preview.fileName, props.preview.extension));
const sourceContent = computed(() => props.preview.textContent ?? "");
const lineCount = computed(() => sourceContent.value.split(/\r\n|\r|\n/).length);
const lineNumbers = computed(() => Array.from({ length: lineCount.value }, (_, index) => index + 1).join("\n"));
const lineNumberWidth = computed(() => `${Math.max(3, String(lineCount.value).length) + 4}ch`);
const highlightedContent = computed(() => {
  if (!syntax.value || props.preview.textContent === undefined) return undefined;
  return highlightPreviewContent(props.preview.textContent, syntax.value);
});
const fullscreen = ref(props.defaultFullscreen);
const previewScroller = ref<{ scrollTop: number; scrollLeft: number }>();
let previousBodyOverflow = "";
let previousDocumentOverflow = "";
const handleKeydown = (event: { key: string; preventDefault: () => void; stopPropagation: () => void }) => {
  if (event.key !== "Escape") return;
  event.preventDefault();
  event.stopPropagation();
  emit("close");
};

onMounted(() => {
  previousBodyOverflow = window.document.body.style.overflow;
  previousDocumentOverflow = window.document.documentElement.style.overflow;
  window.document.body.style.overflow = "hidden";
  window.document.documentElement.style.overflow = "hidden";
  window.addEventListener("keydown", handleKeydown, true);
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", handleKeydown, true);
  window.document.body.style.overflow = previousBodyOverflow;
  window.document.documentElement.style.overflow = previousDocumentOverflow;
});

async function toggleFullscreen() {
  const scrollTop = previewScroller.value?.scrollTop ?? 0;
  const scrollLeft = previewScroller.value?.scrollLeft ?? 0;
  fullscreen.value = !fullscreen.value;
  await nextTick();
  if (previewScroller.value) {
    previewScroller.value.scrollTop = scrollTop;
    previewScroller.value.scrollLeft = scrollLeft;
  }
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function checksumLabel(status?: string) {
  return status === "modified" ? "Gewijzigd" : status === "missing" ? "Ontbreekt" : status === "unexpected" ? "Hoort niet aanwezig te zijn" : "Scan mislukt";
}
</script>

<template>
  <div :class="['modal-backdrop', 'file-preview-backdrop', { fullscreen }]" role="presentation" @click.self="$emit('close')">
    <section :class="['modal', 'preview-modal', { fullscreen }]" role="dialog" aria-modal="true" aria-label="Bestandspreview">
      <div class="preview-window-actions">
        <button class="icon-button" :aria-label="fullscreen ? 'Fullscreen verlaten' : 'Fullscreen openen'" :title="fullscreen ? 'Fullscreen verlaten' : 'Fullscreen openen'" @click="toggleFullscreen">
          <Minimize2 v-if="fullscreen" :size="18" />
          <Maximize2 v-else :size="18" />
        </button>
        <button class="icon-button" aria-label="Sluiten" title="Sluiten" @click="$emit('close')"><X :size="18" /></button>
      </div>
      <h2>{{ preview.fileName }}</h2>
      <code class="preview-path">{{ preview.relativePath }}</code>
      <dl class="preview-metadata">
        <div><dt>Grootte</dt><dd>{{ formatBytes(preview.sizeBytes) }}</dd></div>
        <div><dt>Gewijzigd</dt><dd>{{ formatDate(preview.modifiedAt) }}</dd></div>
        <div><dt>Type</dt><dd>{{ preview.fileType }}</dd></div>
        <div v-if="preview.finding.checksumStatus"><dt>Checksum</dt><dd>{{ checksumLabel(preview.finding.checksumStatus) }}</dd></div>
      </dl>
      <p v-if="preview.truncated" class="preview-warning">De preview is afgekapt op 256 KB.</p>
      <p v-if="preview.binary" class="preview-warning">Dit bestand kan niet veilig als tekst worden weergegeven.</p>
      <div v-else ref="previewScroller" class="file-preview" role="region" aria-label="Bestandsinhoud met regelnummers" tabindex="0">
        <pre class="file-preview-line-numbers" aria-hidden="true" :style="{ minWidth: lineNumberWidth }"><code>{{ lineNumbers }}</code></pre>
        <pre class="file-preview-code"><!-- highlight.js escapes the untrusted source before returning markup. --><code v-if="syntax" class="hljs" :data-syntax="syntax" v-html="highlightedContent"></code><code v-else data-syntax="plain">{{ preview.textContent }}</code></pre>
      </div>
      <div class="modal-actions"><button class="button secondary" @click="$emit('close')">Sluiten</button><button v-if="canDelete" class="button danger" @click="$emit('delete')"><Trash2 :size="14" /> Bestand verwijderen</button></div>
    </section>
  </div>
</template>
