// Client for MediSIEM's own device-metadata API (groups + OS-category
// overrides) — unlike wazuhApi.ts, hits the MediSIEM backend directly.

import type { OsCategory } from './wazuhApi';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';

export interface DeviceGroup {
  id: string;
  name: string;
  description?: string;
  deviceCount: number;
  createdAt: string;
}

export interface TaggedMedicalDevice {
  id: string;
  deviceName: string;
  deviceType: string;
  department: string;
}

export interface DeviceMeta {
  id: string;
  agentId: string;
  agentName?: string;
  groups: string[];
  osCategoryOverride: OsCategory | null;
  medicalDevice: TaggedMedicalDevice | null;
}

async function request<T>(path: string, token: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options?.headers ?? {}),
    },
  });

  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error((json as { error?: string }).error || `HTTP ${res.status}`);
  return json as T;
}

// ── Groups ───────────────────────────────────────────────────────────────────
export async function getDeviceGroups(token: string): Promise<DeviceGroup[]> {
  const data = await request<{ groups: DeviceGroup[] }>('/device-groups', token);
  return data.groups;
}

export async function createDeviceGroup(token: string, name: string, description = ''): Promise<DeviceGroup> {
  const data = await request<{ group: DeviceGroup }>('/device-groups', token, {
    method: 'POST',
    body: JSON.stringify({ name, description }),
  });
  return data.group;
}

export async function updateDeviceGroup(
  token: string,
  id: string,
  payload: { name?: string; description?: string }
): Promise<DeviceGroup> {
  const data = await request<{ group: DeviceGroup }>(`/device-groups/${id}`, token, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  return data.group;
}

export async function deleteDeviceGroup(token: string, id: string): Promise<void> {
  await request<{ message: string }>(`/device-groups/${id}`, token, { method: 'DELETE' });
}

// ── Per-agent metadata ──────────────────────────────────────────────────────
export async function getDeviceMeta(token: string): Promise<DeviceMeta[]> {
  const data = await request<{ devices: DeviceMeta[] }>('/devices/meta', token);
  return data.devices;
}

export async function setAgentGroups(
  token: string,
  agentId: string,
  groups: string[],
  agentName?: string
): Promise<DeviceMeta> {
  const data = await request<{ device: DeviceMeta }>(`/devices/${agentId}/groups`, token, {
    method: 'PUT',
    body: JSON.stringify({ groups, agentName }),
  });
  return data.device;
}

export async function setAgentOsCategoryOverride(
  token: string,
  agentId: string,
  osCategory: OsCategory | null
): Promise<DeviceMeta> {
  const data = await request<{ device: DeviceMeta }>(`/devices/${agentId}/os-category`, token, {
    method: 'PATCH',
    body: JSON.stringify({ osCategory }),
  });
  return data.device;
}

export async function setAgentMedicalDeviceTag(
  token: string,
  agentId: string,
  medicalDeviceId: string | null,
  agentName?: string
): Promise<DeviceMeta> {
  const data = await request<{ device: DeviceMeta }>(`/devices/${agentId}/medical-device`, token, {
    method: 'PUT',
    body: JSON.stringify({ medicalDeviceId, agentName }),
  });
  return data.device;
}
