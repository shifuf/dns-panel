<template>
  <div class="bento-grid">
    <!-- Hero header -->
    <section class="bento-hero col-span-12">
      <div class="flex flex-col gap-6 md:flex-row md:items-start">
        <div class="min-w-0 flex-1">
          <div class="section-badge">
            <span class="dot" />
            <span class="label">Platform Deployments</span>
          </div>
          <h1 class="page-title">平台部署</h1>
          <p class="page-subtitle">证书上传到哪里 · 什么时候过期 · 实时绑定状态</p>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          <NButton size="small" secondary :loading="checkFetching" @click="runCheck">
            <template #icon><Zap :size="14" /></template>
            检查部署状态
          </NButton>
          <NButton size="small" secondary :loading="depFetching" @click="() => queryClient.invalidateQueries({ queryKey: ['ssl-platform-deployments'] })">
            <template #icon><RefreshCw :size="14" /></template>
            刷新
          </NButton>
          <NButton size="small" type="primary" @click="showDeploy = true">
            <template #icon><Upload :size="14" /></template>
            新部署
          </NButton>
        </div>
      </div>

      <!-- Stat cards -->
      <div v-if="overview" class="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <article class="bento-card-muted p-4">
          <div class="flex items-center gap-2">
            <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100"><Layers :size="16" class="text-slate-500" /></div>
            <p class="text-xs text-slate-400">部署域名总数</p>
          </div>
          <p class="bento-kpi-value">{{ overview.total }}</p>
        </article>
        <article
          v-for="(stat, p) in overview.byProvider"
          :key="p"
          class="bento-card-muted p-4"
        >
          <div class="flex items-center gap-2">
            <div
              class="flex h-8 w-8 items-center justify-center rounded-lg"
              :class="{
                'bg-emerald-100': p === 'qiniu',
                'bg-amber-100': p === 'upyun',
                'bg-blue-100': p === 'tencent',
                'bg-indigo-100': p === 'edgeone',
              }"
            >
              <Cloud :size="16" :class="{
                'text-emerald-600': p === 'qiniu',
                'text-amber-600': p === 'upyun',
                'text-blue-600': p === 'tencent',
                'text-indigo-600': p === 'edgeone',
              }" />
            </div>
            <p class="text-xs text-slate-400">{{ PLATFORM_LABELS[String(p)] || p }}</p>
          </div>
          <p class="bento-kpi-value">{{ stat.total }}</p>
          <div class="mt-1 flex flex-wrap gap-1">
            <NTag v-if="stat.expiringSoon" size="tiny" type="warning" :bordered="false">临期 {{ stat.expiringSoon }}</NTag>
            <NTag v-if="stat.failed" size="tiny" type="error" :bordered="false">失败 {{ stat.failed }}</NTag>
            <NTag v-if="stat.expired" size="tiny" type="error" :bordered="false">过期 {{ stat.expired }}</NTag>
            <NTag v-if="!stat.failed && !stat.expiringSoon && !stat.expired" size="tiny" type="success" :bordered="false">正常</NTag>
          </div>
        </article>
      </div>
      <NEmpty v-else description="暂无平台部署记录 — 点右上角「新部署」把证书上传到七牛云/又拍云/腾讯云" class="py-12" />
    </section>

    <!-- Filter + live check summary -->
    <section v-if="deployments.length" class="bento-card col-span-12">
      <div class="mb-4">
        <p class="bento-section-title">部署记录</p>
        <p class="bento-section-meta">支持按平台筛选与域名搜索，可实时核对绑定状态</p>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <NSelect v-model:value="filterProvider" :options="providerOptions" size="small" class="!w-44" placeholder="全部平台" clearable />
        <NInput v-model:value="filterDomain" size="small" placeholder="搜索域名..." clearable class="!w-56">
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <div class="flex-1" />
        <span class="text-xs text-slate-400">{{ filtered.length }} / {{ deployments.length }} 条记录</span>
      </div>
      <div v-if="checks.length" class="mt-3 flex flex-wrap items-center gap-2 border-t border-panel-border pt-3">
        <span class="text-xs text-slate-500">实时检查结果：</span>
        <NTag size="tiny" type="success" :bordered="false">已绑定 {{ countBound }}</NTag>
        <NTag v-if="countDrift" size="tiny" type="warning" :bordered="false">漂移 {{ countDrift }}</NTag>
        <NTag v-if="countUnbound" size="tiny" type="error" :bordered="false">未绑定 {{ countUnbound }}</NTag>
        <NTag v-if="countUnchecked" size="tiny" :bordered="false">未核实 {{ countUnchecked }}</NTag>
      </div>
    </section>

    <!-- Deployment cards -->
    <section
      v-for="dep in filtered"
      :key="`${dep.provider}-${dep.id}`"
      class="bento-card col-span-12"
    >
      <div class="flex flex-wrap items-center gap-2.5">
        <div
          class="flex h-9 w-9 items-center justify-center rounded-xl"
          :class="{
            'bg-emerald-100 text-emerald-600': dep.provider === 'qiniu',
            'bg-amber-100 text-amber-600': dep.provider === 'upyun',
            'bg-blue-100 text-blue-600': dep.provider === 'tencent',
            'bg-indigo-100 text-indigo-600': dep.provider === 'edgeone',
          }"
        >
          <Cloud :size="17" />
        </div>
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-[15px] font-semibold text-slate-800">{{ dep.domain }}</span>
            <span class="text-xs text-slate-400">{{ PLATFORM_LABELS[dep.provider] || dep.provider }} · {{ dep.credentialName || dep.credentialId }}</span>
          </div>
        </div>
        <div class="ml-auto flex flex-wrap items-center gap-1.5">
          <NTag size="tiny" :bordered="false" :type="dep.status === 'synced' ? 'success' : dep.status === 'failed' ? 'error' : 'warning'">
            {{ dep.status === 'synced' ? '已同步' : dep.status === 'failed' ? '上传失败' : dep.status }}
          </NTag>
          <NTag v-if="dep.isExpired" size="tiny" type="error" :bordered="false">已过期</NTag>
          <NTag v-else-if="dep.daysRemaining !== null && dep.daysRemaining !== undefined && dep.daysRemaining <= 30" size="tiny" type="warning" :bordered="false">剩 {{ dep.daysRemaining }} 天</NTag>
        </div>
      </div>

      <div class="bento-card-muted mt-3 grid grid-cols-1 gap-x-6 gap-y-1.5 p-3 text-[13px] sm:grid-cols-2">
        <div class="flex items-center justify-between gap-2 sm:justify-start sm:gap-3">
          <span class="shrink-0 text-xs text-slate-400">平台证书</span>
          <span class="truncate font-mono text-xs text-slate-600">{{ dep.platformCertId || '-' }}</span>
        </div>
        <div class="flex items-center justify-between gap-2 sm:justify-start sm:gap-3">
          <span class="shrink-0 text-xs text-slate-400">面板证书</span>
          <span class="truncate font-mono text-xs text-slate-600">{{ dep.certRemoteId || '-' }}</span>
        </div>
        <div class="flex items-center justify-between gap-2 sm:justify-start sm:gap-3">
          <span class="shrink-0 text-xs text-slate-400">到期时间</span>
          <span class="text-xs text-slate-600">{{ fmt(dep?.notAfter) }}</span>
        </div>
        <div class="flex items-center justify-between gap-2 sm:justify-start sm:gap-3">
          <span class="shrink-0 text-xs text-slate-400">上传于</span>
          <span class="text-xs text-slate-600">{{ fmt(dep?.uploadedAt || dep?.syncedAt) }}</span>
        </div>
      </div>

      <!-- Live check block -->
      <div
        v-if="checkFor(dep)"
        class="mt-3 rounded-xl border p-3 text-[13px]"
        :class="checkFor(dep)!.drift ? 'border-amber-300 bg-amber-50/60' : checkFor(dep)!.live?.bound ? 'border-emerald-200 bg-emerald-50/50' : 'border-panel-border'"
      >
        <div class="flex flex-wrap items-center gap-2">
          <ShieldCheck v-if="checkFor(dep)!.live?.bound && !checkFor(dep)!.drift" :size="15" class="text-emerald-600" />
          <AlertTriangle v-else-if="checkFor(dep)!.drift" :size="15" class="text-amber-600" />
          <XCircle v-else :size="15" class="text-red-500" />
          <span class="text-xs font-semibold text-slate-600">实时绑定</span>
          <NTag v-if="!checkFor(dep)!.checked" size="tiny" type="error" :bordered="false">检查失败</NTag>
          <NTag v-else-if="checkFor(dep)!.drift" size="tiny" type="warning" :bordered="false">证书漂移</NTag>
          <NTag v-else-if="checkFor(dep)!.live?.bound" size="tiny" type="success" :bordered="false">已绑定</NTag>
          <NTag v-else size="tiny" type="error" :bordered="false">未绑定</NTag>
          <NTag v-if="checkFor(dep)!.live?.https === false && checkFor(dep)!.live?.bound" size="tiny" type="warning" :bordered="false">HTTPS 未开启</NTag>
          <span v-if="checkFor(dep)!.live?.notAfter" class="ml-auto text-xs text-slate-400">
            实际到期 {{ fmt(checkFor(dep)?.live?.notAfter) }}
          </span>
        </div>
        <p v-if="checkFor(dep)!.live?.certificateId" class="mt-1.5 text-xs text-slate-500">
          平台当前证书 <span class="font-mono">{{ checkFor(dep)!.live!.certificateId }}</span>
          <span v-if="checkFor(dep)!.live!.commonName">（{{ checkFor(dep)!.live!.commonName }}）</span>
        </p>
        <p v-if="checkFor(dep)!.drift" class="mt-1 text-xs text-amber-700">
          平台实际绑定的证书与面板记录不一致——可能有人在该平台手动更换过证书，或续期后未同步成功。
        </p>
        <p v-if="checkFor(dep)!.error" class="mt-1 break-all text-xs text-red-500">{{ checkFor(dep)!.error }}</p>
        <p v-if="checkFor(dep)!.live?.error" class="mt-1 break-all text-xs text-red-500">{{ checkFor(dep)!.live!.error }}</p>
      </div>

      <p v-if="dep.lastError" class="mt-2 break-all text-xs text-red-500">{{ dep.lastError }}</p>

      <div v-if="!dep.isEdgeOne" class="mt-3 flex justify-end gap-2 border-t border-panel-border pt-3">
        <NButton size="tiny" quaternary type="error" :loading="delMutation.isPending.value && delMutation.variables.value === dep.id" @click="delMutation.mutate(dep.id)">
          <template #icon><Trash2 :size="12" /></template>
          删除记录
        </NButton>
      </div>
    </section>

    <!-- Deploy modal -->
    <PlatformDeployModal v-model:show="showDeploy" @deployed="onDeployed" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NTag, NSelect, NInput, NEmpty, useMessage } from 'naive-ui';
import { RefreshCw, Search, Upload, Zap, Globe, Cloud, Layers, ShieldCheck, AlertTriangle, XCircle, Trash2 } from 'lucide-vue-next';
import {
  getPlatformDeployments, deletePlatformDeployment, checkPlatformDeployments,
} from '@/services/ssl';
import type {
  PlatformDeployment, PlatformDeploymentsResponse, PlatformBindingCheck,
} from '@/services/ssl';
import PlatformDeployModal from '@/components/SSL/PlatformDeployModal.vue';
import { formatDateTime } from '@/utils/formatters';

function fmt(v?: string | null) {
  if (!v) return '-';
  return formatDateTime(v);
}

const message = useMessage();
const queryClient = useQueryClient();

const PLATFORM_LABELS: Record<string, string> = {
  qiniu: '七牛云',
  upyun: '又拍云',
  tencent: '腾讯云',
  edgeone: '腾讯云 EdgeOne',
};

const { data: platformDeploymentsData, isFetching: depFetching } = useQuery({
  queryKey: ['ssl-platform-deployments'],
  queryFn: async (): Promise<PlatformDeploymentsResponse | undefined> => {
    const res = await getPlatformDeployments();
    return res.data;
  },
});

const deployments = computed<PlatformDeployment[]>(() => {
  const payload = platformDeploymentsData.value as unknown as { deployments?: PlatformDeployment[] } | PlatformDeployment[] | undefined;
  if (Array.isArray(payload)) return payload;
  return payload?.deployments || [];
});
const overview = computed(() => platformDeploymentsData.value?.overview);

const filterProvider = ref<string | null>(null);
const filterDomain = ref('');

const providerOptions = computed(() => {
  const set = new Set<string>();
  for (const d of deployments.value) set.add(String(d.provider));
  return [...set].map(p => ({ label: PLATFORM_LABELS[p] || p, value: p }));
});

const filtered = computed(() =>
  deployments.value.filter(d =>
    (!filterProvider.value || d.provider === filterProvider.value) &&
    (!filterDomain.value || (d.domain || '').toLowerCase().includes(filterDomain.value.toLowerCase()))
  ),
);

// live check results
const checks = ref<PlatformBindingCheck[]>([]);
const checkFetching = ref(false);
const checkFor = (dep: PlatformDeployment): PlatformBindingCheck | null => {
  const list = checks.value.filter(c2 => c2.domain === dep.domain && c2.provider === dep.provider);
  return list.length ? list[list.length - 1] : null;
};
async function runCheck() {
  checkFetching.value = true;
  try {
    const res = await checkPlatformDeployments();
    checks.value = res.data?.checks || [];
    const checked = res.data?.checked ?? 0;
    const total = res.data?.total ?? 0;
    const drift = res.data?.drift ?? 0;
    let msg = `检查完成：${checked}/${total} 个域名状态已核实`;
    if (drift) msg += `，${drift} 个漂移`;
    message.success(msg);
  } catch (err: any) {
    message.error(String(err));
  } finally {
    checkFetching.value = false;
  }
}

const countBound = computed(() => checks.value.filter(c2 => c2.checked && c2.live?.bound && !c2.drift).length);
const countDrift = computed(() => checks.value.filter(c2 => c2.drift).length);
const countUnbound = computed(() => checks.value.filter(c2 => c2.checked && c2.live && c2.live.bound === false).length);
const countUnchecked = computed(() => checks.value.filter(c2 => !c2.checked).length);

const delMutation = useMutation({
  mutationFn: (id: number) => deletePlatformDeployment(id),
  onSuccess: (res: any) => {
    message.success(res?.message || '已删除部署记录');
    queryClient.invalidateQueries({ queryKey: ['ssl-platform-deployments'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const showDeploy = ref(false);
function onDeployed() {
  queryClient.invalidateQueries({ queryKey: ['ssl-platform-deployments'] });
}
</script>
