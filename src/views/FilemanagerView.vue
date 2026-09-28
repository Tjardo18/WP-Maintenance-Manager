<script setup lang="ts">
import { onUnmounted, ref, watch } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { FolderOpen, LoaderCircle } from "@lucide/vue";
import { appApi } from "../services/tauri";
import type { FilemanagerContext } from "../types/filemanager";
import { errorMessage } from "../utils/errors";

const route = useRoute();
const context = ref<FilemanagerContext>();
const loading = ref(false);
const error = ref<string>();
let requestId = 0;

watch(() => route.params.id, async (siteId) => {
  const request = ++requestId;
  context.value = undefined;
  error.value = undefined;
  loading.value = true;
  try {
    if (typeof siteId !== "string" || !siteId) throw new Error("Website niet gevonden.");
    const result = await appApi.getFilemanagerContext(siteId);
    if (request !== requestId) return;
    if (result.siteId !== siteId) throw new Error("De websitecontext komt niet overeen.");
    context.value = result;
  } catch (cause) {
    if (request === requestId) error.value = errorMessage(cause);
  } finally {
    if (request === requestId) loading.value = false;
  }
}, { immediate: true });

onUnmounted(() => { requestId += 1; });
</script>

<template>
  <section class="page-heading">
    <div><h2>Filemanager</h2><p v-if="context">{{ context.siteName }} · {{ context.siteUrl }}</p></div>
    <RouterLink v-if="context" class="button secondary" :to="`/websites/${context.siteId}`">Terug naar website</RouterLink>
    <RouterLink v-else class="button secondary" to="/websites">Alle websites</RouterLink>
  </section>
  <p v-if="error" class="error-banner" role="alert">{{ error }}</p>
  <section v-else class="card" :aria-busy="loading">
    <div v-if="loading" class="empty-state"><LoaderCircle class="spin" :size="32" /><p>Website laden…</p></div>
    <div v-else-if="context" class="empty-state">
      <FolderOpen :size="38" />
      <h3>Filemanager voor {{ context.siteName }}</h3>
      <p>De filemanager is in ontwikkeling. Bestandsbeheer wordt in volgende fases beschikbaar.</p>
    </div>
  </section>
</template>
