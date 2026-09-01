import { useEffect, useState } from 'react';
import { getVersion } from '@tauri-apps/api/app';

let cached: string | null = null;

export function useAppVersion(): string {
  const [version, setVersion] = useState<string>(cached ?? '');

  useEffect(() => {
    if (cached !== null) return;
    let alive = true;
    getVersion()
      .then(v => {
        cached = v;
        if (alive) setVersion(v);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  return version;
}

export function formatVersion(version: string): string {
  return version ? `v${version}` : '';
}
