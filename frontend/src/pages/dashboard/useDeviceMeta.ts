// frontend/src/pages/dashboard/useDeviceMeta.ts
import { useState, useEffect, useCallback } from 'react';
import type { OsCategory } from './wazuhApi';
import {
  DeviceGroup, DeviceMeta,
  getDeviceGroups, createDeviceGroup, updateDeviceGroup, deleteDeviceGroup,
  getDeviceMeta, setAgentGroups, setAgentOsCategoryOverride, setAgentMedicalDeviceTag,
} from './deviceApi';

export interface UseDeviceMetaReturn {
  groups:        DeviceGroup[];
  deviceMeta:    DeviceMeta[];
  loading:       boolean;
  error:         string | null;

  refresh:       () => Promise<void>;

  createGroup:   (name: string, description?: string) => Promise<DeviceGroup>;
  renameGroup:   (id: string, name: string) => Promise<void>;
  deleteGroup:   (id: string) => Promise<void>;

  assignGroups:  (agentId: string, groups: string[], agentName?: string) => Promise<void>;
  setOsOverride: (agentId: string, osCategory: OsCategory | null) => Promise<void>;
  tagMedicalDevice: (agentId: string, medicalDeviceId: string | null, agentName?: string) => Promise<void>;
}

export function useDeviceMeta(token: string | null): UseDeviceMetaReturn {
  const [groups,     setGroups]     = useState<DeviceGroup[]>([]);
  const [deviceMeta, setDeviceMeta] = useState<DeviceMeta[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [g, m] = await Promise.all([getDeviceGroups(token), getDeviceMeta(token)]);
      setGroups(g);
      setDeviceMeta(m);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load device metadata');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { refresh(); }, [refresh]);

  const createGroup = useCallback(async (name: string, description = '') => {
    if (!token) throw new Error('Not authenticated.');
    const group = await createDeviceGroup(token, name, description);
    setGroups((prev) => [...prev, group].sort((a, b) => a.name.localeCompare(b.name)));
    return group;
  }, [token]);

  const renameGroup = useCallback(async (id: string, name: string) => {
    if (!token) throw new Error('Not authenticated.');
    const before = groups.find((g) => g.id === id);
    const updated = await updateDeviceGroup(token, id, { name });
    setGroups((prev) => prev.map((g) => (g.id === id ? updated : g)).sort((a, b) => a.name.localeCompare(b.name)));
    // Reflect the rename in any devices currently holding the old name, so the
    // UI doesn't wait for a full refresh() to catch up.
    if (before && before.name !== updated.name) {
      setDeviceMeta((prev) => prev.map((d) => (
        d.groups.includes(before.name)
          ? { ...d, groups: d.groups.map((n) => (n === before.name ? updated.name : n)) }
          : d
      )));
    }
  }, [token, groups]);

  const deleteGroup = useCallback(async (id: string) => {
    if (!token) throw new Error('Not authenticated.');
    const target = groups.find((g) => g.id === id);
    await deleteDeviceGroup(token, id);
    setGroups((prev) => prev.filter((g) => g.id !== id));
    if (target) {
      setDeviceMeta((prev) => prev.map((d) => (
        d.groups.includes(target.name) ? { ...d, groups: d.groups.filter((n) => n !== target.name) } : d
      )));
    }
  }, [token, groups]);

  const assignGroups = useCallback(async (agentId: string, newGroups: string[], agentName?: string) => {
    if (!token) throw new Error('Not authenticated.');
    const before = deviceMeta.find((d) => d.agentId === agentId)?.groups ?? [];
    const updated = await setAgentGroups(token, agentId, newGroups, agentName);
    setDeviceMeta((prev) => {
      const idx = prev.findIndex((d) => d.agentId === agentId);
      if (idx === -1) return [...prev, updated];
      const next = [...prev];
      next[idx] = updated;
      return next;
    });
    // Keep each group's deviceCount in sync locally rather than refetching the
    // whole group list on every single assignment.
    const added = updated.groups.filter((g) => !before.includes(g));
    const removed = before.filter((g) => !updated.groups.includes(g));
    if (added.length || removed.length) {
      setGroups((prev) => prev.map((g) => {
        if (added.includes(g.name)) return { ...g, deviceCount: g.deviceCount + 1 };
        if (removed.includes(g.name)) return { ...g, deviceCount: Math.max(0, g.deviceCount - 1) };
        return g;
      }));
    }
  }, [token, deviceMeta]);

  const setOsOverride = useCallback(async (agentId: string, osCategory: OsCategory | null) => {
    if (!token) throw new Error('Not authenticated.');
    const updated = await setAgentOsCategoryOverride(token, agentId, osCategory);
    setDeviceMeta((prev) => {
      const idx = prev.findIndex((d) => d.agentId === agentId);
      if (idx === -1) return [...prev, updated];
      const next = [...prev];
      next[idx] = updated;
      return next;
    });
  }, [token]);

  const tagMedicalDevice = useCallback(async (agentId: string, medicalDeviceId: string | null, agentName?: string) => {
    if (!token) throw new Error('Not authenticated.');
    const updated = await setAgentMedicalDeviceTag(token, agentId, medicalDeviceId, agentName);
    setDeviceMeta((prev) => {
      const idx = prev.findIndex((d) => d.agentId === agentId);
      if (idx === -1) return [...prev, updated];
      const next = [...prev];
      next[idx] = updated;
      return next;
    });
  }, [token]);

  return {
    groups, deviceMeta, loading, error, refresh,
    createGroup, renameGroup, deleteGroup,
    assignGroups, setOsOverride, tagMedicalDevice,
  };
}
