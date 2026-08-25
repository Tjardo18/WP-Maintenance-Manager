<script setup lang="ts">
import { AlertTriangle, X } from "@lucide/vue";
defineProps<{ title: string; confirmLabel?: string; busy?: boolean }>();
defineEmits<{ confirm: []; cancel: [] }>();
</script>
<template>
  <div class="modal-backdrop" role="presentation" @click.self="$emit('cancel')">
    <section class="modal" role="dialog" aria-modal="true" :aria-label="title">
      <button class="icon-button modal-close" aria-label="Sluiten" @click="$emit('cancel')"><X :size="18" /></button>
      <span class="modal-icon"><AlertTriangle :size="23" /></span>
      <h2>{{ title }}</h2><div class="modal-copy"><slot /></div>
      <div class="modal-actions"><button class="button secondary" :disabled="busy" @click="$emit('cancel')">Annuleren</button><button class="button primary" :disabled="busy" @click="$emit('confirm')">{{ busy ? "Bezig…" : (confirmLabel ?? "Bevestigen") }}</button></div>
    </section>
  </div>
</template>
