<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { Code2, Eye, FileImage, Maximize2, Minimize2, Trash2, X } from "@lucide/vue";
import type { FilePreview, MarkdownPreviewMode } from "../types";
import { inspectBinaryImage } from "../services/binaryInspector";
import { highlightPreviewContent, previewSyntax } from "../services/fileSyntax";
import { binaryImageDataUrl, isImagePreviewExtension } from "../services/imagePreview";
import { renderMarkdownPreview } from "../services/markdownPreview";
import { svgPreviewDataUrl } from "../services/svgPreview";
import { appApi } from "../services/tauri";
import { formatDate } from "../utils/format";

const props = withDefaults(defineProps<{ preview: FilePreview; defaultFullscreen?: boolean; defaultMarkdownMode?: MarkdownPreviewMode }>(), {
  defaultFullscreen: false,
  defaultMarkdownMode: "raw",
});
const emit = defineEmits<{ close: []; delete: [] }>();

const canDelete = computed(() => props.preview.finding.checksumStatus === "unexpected");
const syntax = computed(() => previewSyntax(props.preview.fileName, props.preview.extension));
const isMarkdown = computed(() => syntax.value === "md");
const isSvg = computed(() => syntax.value === "svg");
const isImage = computed(() => isImagePreviewExtension(props.preview.extension ?? props.preview.fileName.match(/\.([^.]+)$/)?.[1]));
const supportsRenderedPreview = computed(() => (isMarkdown.value && !props.preview.binary) || isImage.value);
const previewViewLabel = computed(() => isMarkdown.value ? "Markdownweergave" : isSvg.value ? "SVG-weergave" : "Afbeeldingsweergave");
const sourceContent = computed(() => props.preview.textContent ?? "");
const lineCount = computed(() => sourceContent.value.split(/\r\n|\r|\n/).length);
const lineNumbers = computed(() => Array.from({ length: lineCount.value }, (_, index) => index + 1).join("\n"));
const lineNumberWidth = computed(() => `${Math.max(3, String(lineCount.value).length) + 4}ch`);
const contentMode = ref<MarkdownPreviewMode>(isMarkdown.value ? props.defaultMarkdownMode : "raw");
const highlightedContent = computed(() => {
  if (!syntax.value || props.preview.textContent === undefined) return undefined;
  return highlightPreviewContent(props.preview.textContent, syntax.value);
});
const renderedMarkdown = computed(() => isMarkdown.value && contentMode.value === "preview" ? renderMarkdownPreview(sourceContent.value) : "");
const renderedImage = computed(() => {
  if (!isImage.value || contentMode.value !== "preview") return undefined;
  return isSvg.value
    ? svgPreviewDataUrl(sourceContent.value)
    : binaryImageDataUrl(props.preview.imageMimeType, props.preview.imageDataBase64);
});
const binaryInspection = computed(() => props.preview.binary && isImage.value
  ? inspectBinaryImage(props.preview.rawDataBase64 ?? props.preview.imageDataBase64)
  : undefined);
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

type LinkTarget = { getAttribute: (name: string) => string | null };
function isLinkTarget(value: unknown): value is LinkTarget {
  return typeof value === "object" && value !== null && "getAttribute" in value && typeof (value as LinkTarget).getAttribute === "function";
}

function openMarkdownLink(event: { composedPath: () => unknown[]; preventDefault: () => void }) {
  const link = event.composedPath().find((item) => isLinkTarget(item) && item.getAttribute("href") !== null) as LinkTarget | undefined;
  if (!link) return;
  event.preventDefault();
  const href = link.getAttribute("href");
  if (href && /^https?:\/\//i.test(href)) void appApi.openExternalUrl(href).catch(() => undefined);
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
      <p v-if="preview.truncated" class="preview-warning">De preview is afgekapt op de veilige bestandsgroottelimiet.</p>
      <p v-if="preview.binary && !isImage" class="preview-warning">Dit bestand kan niet veilig als tekst worden weergegeven.</p>
      <div v-if="supportsRenderedPreview" class="preview-mode-toggle" role="group" :aria-label="previewViewLabel">
        <button type="button" :class="{ active: contentMode === 'raw' }" :aria-pressed="contentMode === 'raw'" @click="contentMode = 'raw'"><Code2 :size="14" /> Raw</button>
        <button type="button" :class="{ active: contentMode === 'preview' }" :aria-pressed="contentMode === 'preview'" @click="contentMode = 'preview'"><Eye :size="14" /> Preview</button>
      </div>
      <div v-if="!preview.binary && isMarkdown && contentMode === 'preview'" ref="previewScroller" class="markdown-preview" role="region" aria-label="Gerenderde Markdown-preview" tabindex="0" v-html="renderedMarkdown" @click="openMarkdownLink"></div>
      <div v-else-if="isImage && contentMode === 'preview'" ref="previewScroller" :class="['image-preview', { 'svg-preview': isSvg }]" role="region" :aria-label="`Gerenderde afbeeldingspreview van ${preview.fileName}`" tabindex="0">
        <img v-if="renderedImage" :src="renderedImage" :alt="`Preview van ${preview.fileName}`" draggable="false" />
        <p v-else class="image-preview-error">Deze afbeelding kan niet worden weergegeven. De Raw-weergave blijft beschikbaar.</p>
      </div>
      <div v-else-if="!preview.binary" ref="previewScroller" class="file-preview" role="region" aria-label="Bestandsinhoud met regelnummers" tabindex="0">
        <pre class="file-preview-line-numbers" aria-hidden="true" :style="{ minWidth: lineNumberWidth }"><code>{{ lineNumbers }}</code></pre>
        <pre class="file-preview-code"><!-- highlight.js escapes the untrusted source before returning markup. --><code v-if="syntax" class="hljs" :data-syntax="syntax" v-html="highlightedContent"></code><code v-else data-syntax="plain">{{ preview.textContent }}</code></pre>
      </div>
      <div v-else-if="isImage" ref="previewScroller" class="binary-inspector" role="region" aria-label="Binaire afbeeldingsanalyse" tabindex="0">
        <div class="binary-inspector-heading"><FileImage :size="25" aria-hidden="true" /><div><strong>Binaire Raw-analyse</strong><p>De oorspronkelijke bytes worden alleen-lezen onderzocht; het bestand zelf blijft ongewijzigd.</p></div></div>
        <template v-if="binaryInspection">
          <section class="binary-inspector-section"><h3>Verdachte signalen <span>{{ binaryInspection.suspiciousMatches.length }}</span></h3><p v-if="binaryInspection.suspiciousMatches.length === 0" class="binary-inspector-empty">Geen bekende tekstpatronen of extra gegevens na een herkend bestandseinde gevonden. Dit is geen garantie dat het bestand veilig is.</p><ul v-else class="binary-suspicious-list"><li v-for="match in binaryInspection.suspiciousMatches" :key="`${match.offset}-${match.label}`"><strong>{{ match.label }}</strong><code>{{ match.offsetLabel }}</code><p>{{ match.snippet }}</p></li></ul></section>
          <section class="binary-inspector-section"><h3>Leesbare tekst</h3><pre v-if="binaryInspection.readableText" class="readable-binary-text">{{ binaryInspection.readableText }}</pre><p v-else class="binary-inspector-empty">In de beschikbare bytes is geen aaneengesloten leesbare tekst gevonden.</p><small v-if="binaryInspection.readableTextTruncated">De tekstweergave is begrensd om de preview responsief te houden.</small></section>
          <details class="binary-hex-section"><summary>Hex-weergave van {{ formatBytes(binaryInspection.byteLength) }}</summary><pre>{{ binaryInspection.hexDump }}</pre><small v-if="binaryInspection.hexDumpTruncated">De hexweergave bevat het begin, het einde en gebieden rond verdachte signalen.</small></details>
        </template>
        <p v-else class="binary-inspector-empty">De oorspronkelijke bytes zijn niet beschikbaar voor analyse, bijvoorbeeld omdat het bestand groter is dan de veilige previewlimiet.</p>
      </div>
      <div v-else ref="previewScroller" class="binary-file-preview" role="region" aria-label="Binaire bestandsinhoud" tabindex="0">
        <FileImage :size="30" aria-hidden="true" />
        <div><strong>Binair bestand</strong><p>Dit formaat bevat geen leesbare broncode. De oorspronkelijke bytes worden niet als tekst of kunstmatige syntax weergegeven.</p><code v-if="preview.imageMimeType">{{ preview.imageMimeType }}</code></div>
      </div>
      <div class="modal-actions"><button class="button secondary" @click="$emit('close')">Sluiten</button><button v-if="canDelete" class="button danger" @click="$emit('delete')"><Trash2 :size="14" /> Bestand verwijderen</button></div>
    </section>
  </div>
</template>
