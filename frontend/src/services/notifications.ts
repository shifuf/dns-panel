import api from './api';
import type { ApiResponse } from '@/types';

export type NotificationChannelType =
  | 'email'
  | 'webhook'
  | 'wecom'
  | 'dingtalk'
  | 'feishu'
  | 'telegram'
  | 'inapp';

export interface NotificationChannel {
  type: NotificationChannelType;
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface InAppNotification {
  id: number;
  level: string;
  title: string;
  message?: string | null;
  status: 'unread' | 'read';
  meta?: Record<string, unknown> | null;
  createdAt: string;
}

export async function getNotificationSettings(): Promise<
  ApiResponse<{ enabled: boolean; channels: NotificationChannel[] }>
> {
  return api.get('/notifications/settings') as Promise<
    ApiResponse<{ enabled: boolean; channels: NotificationChannel[] }>
  >;
}

export async function updateNotificationSettings(data: {
  enabled?: boolean;
  channels?: NotificationChannel[];
}): Promise<ApiResponse<{ enabled: boolean; channels: NotificationChannel[] }>> {
  return api.put('/notifications/settings', data) as Promise<
    ApiResponse<{ enabled: boolean; channels: NotificationChannel[] }>
  >;
}

export async function testNotification(data: {
  channel: NotificationChannel;
  title?: string;
  content?: string;
}): Promise<ApiResponse<{ results: Array<{ channel: string; success: boolean; error?: string }> }>> {
  return api.post('/notifications/test', data) as Promise<
    ApiResponse<{ results: Array<{ channel: string; success: boolean; error?: string }> }>
  >;
}

export async function listInAppNotifications(params?: {
  status?: 'unread' | 'read' | 'all';
  limit?: number;
}): Promise<ApiResponse<{ items: InAppNotification[]; unread: number }>> {
  return api.get('/notifications/inbox', { params }) as Promise<
    ApiResponse<{ items: InAppNotification[]; unread: number }>
  >;
}

export async function markInAppRead(id?: number): Promise<ApiResponse<{ ok: boolean }>> {
  return api.post('/notifications/inbox/read', id ? { id } : { all: true }) as Promise<
    ApiResponse<{ ok: boolean }>
  >;
}

export async function scanDomainExpiry(): Promise<
  ApiResponse<{ scanned: number; tracked: number; notified: number }>
> {
  return api.post('/domain-expiry/scan', {}) as Promise<
    ApiResponse<{ scanned: number; tracked: number; notified: number }>
  >;
}

export async function listTrackedDomains(): Promise<
  ApiResponse<{ items: Array<Record<string, unknown>> }>
> {
  return api.get('/domain-expiry/tracked') as Promise<ApiResponse<{ items: Array<Record<string, unknown>> }>>;
}
