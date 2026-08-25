<script setup lang="ts">
import { statusLabel } from "../utils/format";
import type { SiteStatus, StepStatus } from "../types";
defineProps<{ status: SiteStatus | StepStatus }>();
</script>
<template><span class="status-badge" :class="`status-${status}`"><span class="status-dot"></span>{{ statusLabel(status) }}</span></template>
