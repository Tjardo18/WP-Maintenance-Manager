<script setup lang="ts">
import { computed } from "vue";
import { Trash2, X } from "@lucide/vue";
import type { FilePreview } from "../types";
import { highlightPreviewContent, previewSyntax } from "../services/fileSyntax";
import { formatDate } from "../utils/format";

const props = defineProps<{ preview: FilePreview }>();
defineEmits<{ close: []; delete: [] }>();

const canDelete = computed(() => props.preview.finding.checksumStatus === "unexpected");
const syntax = computed(() => previewSyntax(props.preview.fileName, props.preview.extension));
const highlightedContent = computed(() => {
  if (!syntax.value || props.preview.textContent === undefined) return undefined;
  return highlightPreviewContent(props.preview.textContent, syntax.value);
});

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
  <div class="modal-backdrop" role="presentation" @click.self="$emit('close')">
    <section class="modal preview-modal" role="dialog" aria-modal="true" aria-label="Bestandspreview">
      <button class="icon-button modal-close" aria-label="Sluiten" @click="$emit('close')"><X :size="18" /></button>
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
      <pre v-else class="file-preview"><!-- highlight.js escapes the untrusted source before returning markup. --><code v-if="syntax" class="hljs" :data-syntax="syntax" v-html="highlightedContent"></code><code v-else data-syntax="plain">{{ preview.textContent }}</code></pre>
      <div class="modal-actions"><button class="button secondary" @click="$emit('close')">Sluiten</button><button v-if="canDelete" class="button danger" @click="$emit('delete')"><Trash2 :size="14" /> Bestand verwijderen</button></div>
    </section>
  </div>
</template>
