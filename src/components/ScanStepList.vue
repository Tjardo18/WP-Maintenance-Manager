<script setup lang="ts">
import { Check, Clock3, LoaderCircle, Minus, TriangleAlert, X } from "@lucide/vue";
import type { StepStatus } from "../types";

interface DisplayStep {
  key: string;
  label: string;
  status: StepStatus;
  durationMs?: number | null;
  detail?: string;
}

defineProps<{ steps: readonly DisplayStep[] }>();

const statusLabels: Record<StepStatus, string> = {
  pending: "Nog niet uitgevoerd",
  running: "Wordt uitgevoerd",
  success: "Succesvol afgerond",
  warning: "Afgerond met waarschuwing",
  failed: "Mislukt",
  skipped: "Overgeslagen",
};

function hasValidDuration(durationMs?: number | null): durationMs is number {
  return typeof durationMs === "number" && Number.isFinite(durationMs) && durationMs >= 0;
}
</script>

<template>
  <ol class="step-list">
    <li v-for="step in steps" :key="step.key" :class="step.status">
      <span :data-step-status="step.status" role="img" :aria-label="statusLabels[step.status]" :title="statusLabels[step.status]">
        <Check v-if="step.status === 'success'" :size="15" />
        <LoaderCircle v-else-if="step.status === 'running'" class="spin" :size="15" />
        <TriangleAlert v-else-if="step.status === 'warning'" :size="14" />
        <X v-else-if="step.status === 'failed'" :size="15" />
        <Minus v-else-if="step.status === 'skipped'" :size="14" />
        <Clock3 v-else :size="13" />
      </span>
      <strong>{{ step.label }}</strong>
      <small v-if="hasValidDuration(step.durationMs)">{{ step.durationMs }} ms</small>
      <small v-else-if="step.detail">{{ step.detail }}</small>
    </li>
  </ol>
</template>
