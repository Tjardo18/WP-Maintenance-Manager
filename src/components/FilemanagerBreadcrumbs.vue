<script setup lang="ts">
import { Home, ChevronRight } from "@lucide/vue";

const props = defineProps<{ currentPath: string; disabled?: boolean }>();
const emit = defineEmits<{ navigate: [path: string] }>();

const segments = () => props.currentPath.split("/").filter(Boolean).map((name, index, all) => ({ name, path: `/${all.slice(0, index + 1).join("/")}` }));
</script>

<template>
  <nav class="filemanager-breadcrumbs" aria-label="Mappad">
    <button type="button" class="filemanager-crumb root" :disabled="disabled || currentPath === '/'" :aria-current="currentPath === '/' ? 'page' : undefined" title="Hoofdmap" @click="emit('navigate', '/')"><Home :size="15" /><span>Hoofdmap</span></button>
    <template v-for="segment in segments()" :key="segment.path"><ChevronRight class="filemanager-crumb-separator" :size="14" aria-hidden="true" /><button type="button" class="filemanager-crumb" :disabled="disabled || segment.path === currentPath" :aria-current="segment.path === currentPath ? 'page' : undefined" :title="segment.path" @click="emit('navigate', segment.path)">{{ segment.name }}</button></template>
  </nav>
</template>

<style scoped>
.filemanager-breadcrumbs { display: flex; min-width: 0; align-items: center; overflow-x: auto; color: #506159; scrollbar-width: thin; }
.filemanager-crumb { flex: none; border: 0; border-radius: 5px; padding: 4px 5px; background: transparent; color: inherit; font-size: 11px; cursor: pointer; white-space: nowrap; }
.filemanager-crumb:not(:disabled):hover, .filemanager-crumb:not(:disabled):focus-visible { background: #eaf4f0; color: #216c52; outline: 0; }.filemanager-crumb:disabled { color: #263b32; cursor: default; font-weight: 700; }.filemanager-crumb.root { display: inline-flex; align-items: center; gap: 5px; }.filemanager-crumb-separator { flex: none; color: #9ba7a2; }
</style>
