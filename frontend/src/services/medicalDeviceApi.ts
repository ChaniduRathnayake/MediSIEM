// frontend/src/services/medicalDeviceApi.ts
// Client for MediSIEM's onboarded medical device inventory (ventilators,
// infusion pumps, monitors, imaging systems, etc. — MongoDB-backed, managed
// from the admin Devices tab). Same Authorization header pattern as the rest
// of services/*.

import { BASE_URL } from './api';

export type DeviceCriticality = 'low' | 'medium' | 'high' | 'critical';
export type DeviceStatus = 'active' | 'maintenance' | 'decommissioned';

export interface MedicalDevice {
  id: string;
  key: string;
  deviceName: string;
  deviceType: string;
  department: string;
  manufacturer: string;
  model: string;
  serialNumber: string;
  location: string;
  criticality: DeviceCriticality;
  status: DeviceStatus;
  groups: string[];
  notes: string;
  onboardedBy?: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
}

export interface MedicalDeviceInput {
  key: string;
  deviceName: string;
  deviceType: string;
  department: string;
  manufacturer?: string;
  model?: string;
  serialNumber?: string;
  location?: string;
  criticality?: DeviceCriticality;
  notes?: string;
  groups?: string[];
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

export async function getMedicalDevices(token: string): Promise<MedicalDevice[]> {
  const data = await request<{ devices: MedicalDevice[] }>('/medical-devices', token);
  return data.devices;
}

export async function createMedicalDevice(token: string, payload: MedicalDeviceInput): Promise<MedicalDevice> {
  const data = await request<{ device: MedicalDevice }>('/medical-devices', token, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return data.device;
}

export async function updateMedicalDevice(
  token: string,
  id: string,
  payload: Partial<MedicalDeviceInput> & { status?: DeviceStatus }
): Promise<MedicalDevice> {
  const data = await request<{ device: MedicalDevice }>(`/medical-devices/${id}`, token, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  return data.device;
}

export async function setMedicalDeviceGroups(token: string, id: string, groups: string[]): Promise<MedicalDevice> {
  const data = await request<{ device: MedicalDevice }>(`/medical-devices/${id}/groups`, token, {
    method: 'PUT',
    body: JSON.stringify({ groups }),
  });
  return data.device;
}

export async function deleteMedicalDevice(token: string, id: string): Promise<void> {
  await request<{ message: string }>(`/medical-devices/${id}`, token, { method: 'DELETE' });
}
